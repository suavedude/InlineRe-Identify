/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.tokenization.kafka;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Executors;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.delphix.dynamicmasking.tokenization.BatchTokenizer;
import com.delphix.dynamicmasking.tokenization.key.DataEncryptionKeySource;
import com.delphix.dynamicmasking.tokenization.spi.CryptoProvider;
import com.delphix.dynamicmasking.tokenization.spi.CryptoProviderRegistry;
import com.delphix.dynamicmasking.tokenization.spi.TokenizationScheme;
import com.delphix.dynamicmasking.tokenization.spi.TokenizationSchemeRegistry;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;

/**
 * "Streaming" demo entry point: consumes JSON messages from a Kafka input topic, tokenizes the
 * configured sensitive fields via the *same* {@link BatchTokenizer}/SPI core {@link
 * com.delphix.dynamicmasking.tokenization.http.TokenizationHttpServer} and the Redshift Lambda
 * UDF handler use, and produces an envelope carrying both the original and tokenized message to
 * an output topic. A second background loop tails that output topic into a small in-memory
 * buffer, and an embedded HTTP server exposes both directions to the browser demo UI, which can't
 * speak the Kafka wire protocol directly.
 *
 * <p>Plain {@code kafka-clients}, not Kafka Streams -- this is one stateless consume/tokenize/
 * produce loop with no joins, windowing, or state store, so Kafka Streams' topology machinery
 * would be pure overhead. Same "no heavyweight framework" bias as the JDK {@code HttpServer} used
 * by every other standalone entry point in this codebase.
 *
 * <p>Endpoints:
 * <pre>{@code
 * POST /v1/kafka/produce   body is the raw JSON test message -> produced onto KAFKA_INPUT_TOPIC
 * GET  /v1/kafka/messages  -> JSON array of recently tokenized envelopes, newest first
 * GET  /healthz            -> 200 once provider/algorithm/key/Kafka clients are initialized
 * }</pre>
 *
 * <p>Env vars: {@code KAFKA_BOOTSTRAP_SERVERS}, {@code KAFKA_INPUT_TOPIC} (default {@code
 * dynamicmasking.demo.input}), {@code KAFKA_OUTPUT_TOPIC} (default {@code
 * dynamicmasking.demo.output}), {@code SENSITIVE_FIELDS} (default {@code
 * full_name,email,credit_card}), plus the same {@code CRYPTO_PROVIDER}/{@code CIPHER_ALGORITHM}/
 * {@code KEY_SOURCE} (+ DEK) vars every other tokenization entry point already reads.
 */
public final class KafkaMaskingBridge {

    private static final List<String> DEFAULT_SENSITIVE_FIELDS = List.of("full_name", "email", "credit_card");
    private static final int MESSAGE_BUFFER_SIZE = 50;

    private final ObjectMapper mapper = new ObjectMapper();
    private final TokenizationScheme scheme;
    private final byte[] dataEncryptionKey;
    private final List<String> sensitiveFields;
    private final String bootstrapServers;
    private final String inputTopic;
    private final String outputTopic;
    private final KafkaProducer<String, String> producer;

    /** Bounded, newest-first buffer of recently tokenized envelopes, for GET /v1/kafka/messages. */
    private final Deque<Map<String, Object>> recentMessages = new ArrayDeque<>();

    public KafkaMaskingBridge() {
        this.dataEncryptionKey = DataEncryptionKeySource.resolve();
        CryptoProvider provider = CryptoProviderRegistry.resolve(
                System.getenv().getOrDefault("CRYPTO_PROVIDER", "BCFIPS"));
        this.scheme = TokenizationSchemeRegistry.resolve(
                System.getenv().getOrDefault("CIPHER_ALGORITHM", "AES-CBC-CTS"), provider);

        String fieldsEnv = System.getenv().getOrDefault("SENSITIVE_FIELDS", String.join(",", DEFAULT_SENSITIVE_FIELDS));
        this.sensitiveFields = List.of(fieldsEnv.split(","));

        this.bootstrapServers = requireEnv("KAFKA_BOOTSTRAP_SERVERS");
        this.inputTopic = System.getenv().getOrDefault("KAFKA_INPUT_TOPIC", "dynamicmasking.demo.input");
        this.outputTopic = System.getenv().getOrDefault("KAFKA_OUTPUT_TOPIC", "dynamicmasking.demo.output");

        Properties producerProps = new Properties();
        producerProps.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        producerProps.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        producerProps.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        // KafkaProducer is thread-safe for concurrent send() -- shared between the HTTP
        // produce-to-input-topic handler and the masking loop's produce-to-output-topic call.
        this.producer = new KafkaProducer<>(producerProps);
    }

    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "4052"));
        KafkaMaskingBridge app = new KafkaMaskingBridge();

        Thread maskingLoop = new Thread(app::runMaskingLoop, "kafka-masking-loop");
        maskingLoop.setDaemon(true);
        maskingLoop.start();

        Thread outputBufferLoop = new Thread(app::runOutputBufferLoop, "kafka-output-buffer-loop");
        outputBufferLoop.setDaemon(true);
        outputBufferLoop.start();

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/v1/kafka/produce", app.produceHandler());
        server.createContext("/v1/kafka/messages", app.messagesHandler());
        server.createContext("/healthz", exchange -> respond(exchange, 200, "{\"status\":\"ok\"}"));
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("Listening on :" + port);
    }

    /** Consumes KAFKA_INPUT_TOPIC, tokenizes the configured fields, produces onto KAFKA_OUTPUT_TOPIC. */
    private void runMaskingLoop() {
        Properties consumerProps = consumerProps("dynamicmasking-kafka-masking-loop");
        try (KafkaConsumer<String, String> consumer = new KafkaConsumer<>(consumerProps)) {
            consumer.subscribe(List.of(inputTopic));
            while (true) {
                ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(500));
                for (ConsumerRecord<String, String> record : records) {
                    try {
                        Map<String, Object> envelope = tokenizeMessage(record.value());
                        producer.send(new ProducerRecord<>(outputTopic, mapper.writeValueAsString(envelope)));
                    } catch (Exception e) {
                        System.err.println("Failed to process Kafka message: " + e.getMessage());
                    }
                }
            }
        }
    }

    /** Tails KAFKA_OUTPUT_TOPIC into recentMessages, for GET /v1/kafka/messages to serve without touching Kafka per-request. */
    private void runOutputBufferLoop() {
        Properties consumerProps = consumerProps("dynamicmasking-kafka-output-buffer");
        try (KafkaConsumer<String, String> consumer = new KafkaConsumer<>(consumerProps)) {
            consumer.subscribe(List.of(outputTopic));
            while (true) {
                ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(500));
                for (ConsumerRecord<String, String> record : records) {
                    try {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> envelope = mapper.readValue(record.value(), Map.class);
                        synchronized (recentMessages) {
                            recentMessages.addFirst(envelope);
                            while (recentMessages.size() > MESSAGE_BUFFER_SIZE) {
                                recentMessages.removeLast();
                            }
                        }
                    } catch (Exception e) {
                        System.err.println("Failed to buffer Kafka output message: " + e.getMessage());
                    }
                }
            }
        }
    }

    private Properties consumerProps(String groupId) {
        Properties props = new Properties();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ConsumerConfig.GROUP_ID_CONFIG, groupId);
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        // Demo-only convenience -- a fresh consumer group always sees whatever's already on the
        // topic, so a message produced just before this process (re)started still shows up.
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        return props;
    }

    /**
     * Extracts the configured sensitive fields present (and non-null) in {@code messageJson},
     * tokenizes them via {@link BatchTokenizer} (the exact same core the HTTP/Lambda entry points
     * use), and returns {@code {"original": ..., "tokenized": ..., "failureCount": ..., "errors": ...}}.
     * Fields absent from SENSITIVE_FIELDS, or absent/null in the message, pass through unchanged.
     */
    private Map<String, Object> tokenizeMessage(String messageJson) throws IOException {
        @SuppressWarnings("unchecked")
        Map<String, Object> original = mapper.readValue(messageJson, Map.class);

        List<String> presentFields = new ArrayList<>();
        List<String> values = new ArrayList<>();
        for (String field : sensitiveFields) {
            Object value = original.get(field);
            if (original.containsKey(field) && value != null) {
                presentFields.add(field);
                values.add(String.valueOf(value));
            }
        }

        BatchTokenizer.Result result = BatchTokenizer.apply(values, true, scheme, dataEncryptionKey, null);

        Map<String, Object> tokenized = new LinkedHashMap<>(original);
        Map<String, String> errors = new LinkedHashMap<>();
        for (int i = 0; i < presentFields.size(); i++) {
            tokenized.put(presentFields.get(i), result.results.get(i));
            if (result.errors.get(i) != null) {
                errors.put(presentFields.get(i), result.errors.get(i));
            }
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("original", original);
        envelope.put("tokenized", tokenized);
        envelope.put("failureCount", result.failureCount);
        envelope.put("errors", errors);
        return envelope;
    }

    private HttpHandler produceHandler() {
        return exchange -> {
            try {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    respond(exchange, 405, "{\"error\":\"POST required\"}");
                    return;
                }
                byte[] rawBody = exchange.getRequestBody().readAllBytes();
                try {
                    mapper.readTree(rawBody); // validates it's parseable JSON before producing it
                } catch (Exception e) {
                    respond(exchange, 400, "{\"error\":\"request body must be a JSON object\"}");
                    return;
                }
                producer.send(new ProducerRecord<>(inputTopic, new String(rawBody, StandardCharsets.UTF_8)));
                respond(exchange, 200, "{\"success\":true}");
            } finally {
                exchange.close();
            }
        };
    }

    private HttpHandler messagesHandler() {
        return exchange -> {
            try {
                if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                    respond(exchange, 405, "{\"error\":\"GET required\"}");
                    return;
                }
                List<Map<String, Object>> snapshot;
                synchronized (recentMessages) {
                    snapshot = new ArrayList<>(recentMessages);
                }
                respond(exchange, 200, mapper.writeValueAsString(snapshot));
            } finally {
                exchange.close();
            }
        };
    }

    private static void respond(HttpExchange exchange, int status, String json) throws IOException {
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(body);
        }
    }

    private static String requireEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isEmpty()) {
            throw new IllegalStateException(name + " environment variable must be set");
        }
        return value;
    }
}
