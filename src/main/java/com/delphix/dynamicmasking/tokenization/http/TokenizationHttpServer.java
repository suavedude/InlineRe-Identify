/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.tokenization.http;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.delphix.dynamicmasking.onewaymasking.BatchMasker;
import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingScheme;
import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingSchemeRegistry;
import com.delphix.dynamicmasking.tokenization.BatchTokenizer;
import com.delphix.dynamicmasking.tokenization.key.DataEncryptionKeySource;
import com.delphix.dynamicmasking.tokenization.spi.CryptoProvider;
import com.delphix.dynamicmasking.tokenization.spi.CryptoProviderRegistry;
import com.delphix.dynamicmasking.tokenization.spi.TokenizationScheme;
import com.delphix.dynamicmasking.tokenization.spi.TokenizationSchemeRegistry;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

/**
 * Plain REST facade over the same tokenize/detokenize core used by the Delphix plugin ({@link
 * com.delphix.dynamicmasking.tokenization.TokenizationAlgorithm}) and the Redshift Lambda UDF
 * ({@link com.delphix.dynamicmasking.tokenization.lambda.RedshiftUdfHandler}), for any
 * database or application that can make an outbound HTTP call but isn't Redshift and can't
 * invoke a Lambda directly -- self-hosted Postgres via the {@code http} extension, MySQL,
 * Snowflake External Functions, BigQuery Remote Functions, or plain application code. See
 * README.md for per-database integration examples.
 *
 * <p>Endpoints:
 * <pre>{@code
 * POST /v1/tokenize          {"values": ["a", null, "b"]}
 *                            -> {"results": ["tok-a", null, "tok-b"], "failureCount": 0, "errors": [null, null, null]}
 * POST /v1/reidentify         same shape, reverse direction
 * POST /v1/mask/full-name        same request/response shape; one-way (non-reversible) masking,
 * POST /v1/mask/credit-card      each endpoint permanently fixed to one scheme -- see {@link
 * POST /v1/mask/email            #MASK_ENDPOINTS} for the full path-to-scheme list -- there is
 * POST /v1/mask/first-name       no scheme-selector env var, by design: a generic "mask()"
 * POST /v1/mask/last-name        endpoint whose behavior depends on process-wide config is easy
 * POST /v1/mask/date-shift       to point at the wrong data (e.g. running an email through a
 * POST /v1/mask/segment-mapping  scheme meant for names); one endpoint per data shape can't be
 *                                misapplied that way.
 * GET  /healthz                  200 once the configured provider/algorithm/key have been resolved
 * }</pre>
 *
 * <p>Unlike the Lambda handler -- which is deployed twice, once per direction, because a Lambda
 * function has exactly one entry point -- one process here serves both {@code /v1/tokenize} and
 * {@code /v1/reidentify}; direction is which path you call, not a deployment-time choice.
 *
 * <p>Provider/algorithm/key are still process-wide config, same env var names as the Lambda
 * handler: {@code CRYPTO_PROVIDER} (default {@code "BCFIPS"}), {@code CIPHER_ALGORITHM} (default
 * {@code "AES-CBC-CTS"}), {@code KEY_SOURCE} (+ its {@link DataEncryptionKeySource} variants).
 * A null value in {@code "values"} passes through as {@code null} in {@code "results"} without
 * being counted as a failure; a value that fails to tokenize/detokenize comes back {@code null}
 * too, is counted in {@code failureCount}, and gets an explanatory message at the same index in
 * {@code "errors"} (a reidentify failure almost always means the token is corrupted/malformed/not
 * produced under the configured key, since there's no other way for it to fail) -- see {@link
 * BatchTokenizer}.
 *
 * <p>The three {@code /v1/mask/*} endpoints reuse the same key resolved for tokenization; unlike
 * that key, which scheme each one runs is not configurable -- it's fixed in code (see {@link
 * com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingSchemeRegistry}).
 */
public final class TokenizationHttpServer {

    /**
     * URL path segment (under {@code /v1/mask/}) -> the scheme id it's permanently fixed to.
     * Adding a new fixed-scheme endpoint is exactly one entry here -- {@link #main} wires up a
     * context per entry, resolved once at startup the same way {@link #scheme} is.
     */
    private static final Map<String, String> MASK_ENDPOINTS = new LinkedHashMap<>();

    static {
        MASK_ENDPOINTS.put("full-name", "FULL-NAME-MASK");
        MASK_ENDPOINTS.put("credit-card", "CREDIT-CARD-MASK");
        MASK_ENDPOINTS.put("email", "EMAIL-MASK");
        MASK_ENDPOINTS.put("first-name", "FIRST-NAME-LOOKUP");
        MASK_ENDPOINTS.put("last-name", "LAST-NAME-LOOKUP");
        MASK_ENDPOINTS.put("date-shift", "DATE-SHIFT");
        MASK_ENDPOINTS.put("segment-mapping", "SEGMENT-MAPPING");
    }

    private final ObjectMapper mapper = new ObjectMapper();
    private final TokenizationScheme scheme;
    private final byte[] dataEncryptionKey;
    private final Map<String, OneWayMaskingScheme> maskingSchemes;

    public TokenizationHttpServer() {
        this.dataEncryptionKey = DataEncryptionKeySource.resolve();
        CryptoProvider provider = CryptoProviderRegistry.resolve(
                System.getenv().getOrDefault("CRYPTO_PROVIDER", "BCFIPS"));
        this.scheme = TokenizationSchemeRegistry.resolve(
                System.getenv().getOrDefault("CIPHER_ALGORITHM", "AES-CBC-CTS"), provider);

        Map<String, OneWayMaskingScheme> resolved = new LinkedHashMap<>();
        MASK_ENDPOINTS.forEach((path, schemeId) -> resolved.put(path, OneWayMaskingSchemeRegistry.resolve(schemeId)));
        this.maskingSchemes = resolved;
    }

    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "4051"));
        // Resolving provider/algorithm/key here, before the server starts accepting
        // connections, means a bad configuration crashes the process at startup (visible in
        // container logs / orchestrator restart-looping) rather than surfacing as a 500 on the
        // first request.
        TokenizationHttpServer app = new TokenizationHttpServer();

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/v1/tokenize", app.batchHandler(true));
        server.createContext("/v1/reidentify", app.batchHandler(false));
        app.maskingSchemes.forEach((path, maskingScheme) ->
                server.createContext("/v1/mask/" + path, app.maskHandler(maskingScheme)));
        server.createContext("/healthz", exchange -> respond(exchange, 200, "{\"status\":\"ok\"}"));
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("Listening on :" + port);
    }

    private HttpHandler batchHandler(boolean tokenize) {
        return exchange -> {
            try {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    respond(exchange, 405, "{\"error\":\"POST required\"}");
                    return;
                }
                handleBatch(exchange, tokenize);
            } finally {
                exchange.close();
            }
        };
    }

    private HttpHandler maskHandler(OneWayMaskingScheme maskingScheme) {
        return exchange -> {
            try {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    respond(exchange, 405, "{\"error\":\"POST required\"}");
                    return;
                }
                handleMaskBatch(exchange, maskingScheme);
            } finally {
                exchange.close();
            }
        };
    }

    private void handleMaskBatch(HttpExchange exchange, OneWayMaskingScheme maskingScheme) throws IOException {
        BatchRequest request;
        try {
            request = mapper.readValue(exchange.getRequestBody(), BatchRequest.class);
        } catch (Exception e) {
            respond(exchange, 400, "{\"error\":\"request body must be JSON matching {\\\"values\\\": [...]}\"}");
            return;
        }
        if (request.values == null) {
            respond(exchange, 400, "{\"error\":\"'values' is required\"}");
            return;
        }

        BatchMasker.Result result = BatchMasker.apply(
                request.values, maskingScheme, dataEncryptionKey,
                (index, e) -> System.err.println("Row " + index + " failed: " + e));

        BatchResponse response = new BatchResponse();
        response.results = result.results;
        response.failureCount = result.failureCount;
        response.errors = result.errors;
        respond(exchange, 200, mapper.writeValueAsString(response));
    }

    private void handleBatch(HttpExchange exchange, boolean tokenize) throws IOException {
        BatchRequest request;
        try {
            request = mapper.readValue(exchange.getRequestBody(), BatchRequest.class);
        } catch (Exception e) {
            respond(exchange, 400, "{\"error\":\"request body must be JSON matching {\\\"values\\\": [...]}\"}");
            return;
        }
        if (request.values == null) {
            respond(exchange, 400, "{\"error\":\"'values' is required\"}");
            return;
        }

        BatchTokenizer.Result result = BatchTokenizer.apply(
                request.values, tokenize, scheme, dataEncryptionKey,
                (index, e) -> System.err.println("Row " + index + " failed: " + e));

        BatchResponse response = new BatchResponse();
        response.results = result.results;
        response.failureCount = result.failureCount;
        response.errors = result.errors;
        respond(exchange, 200, mapper.writeValueAsString(response));
    }

    private static void respond(HttpExchange exchange, int status, String json) throws IOException {
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(body);
        }
    }

    static final class BatchRequest {
        public List<String> values;
    }

    static final class BatchResponse {
        public List<String> results;
        public int failureCount;
        public List<String> errors;
    }
}
