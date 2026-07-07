/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.inlinereidentify.masking.tokenization.lambda;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.inlinereidentify.masking.tokenization.BatchTokenizer;
import com.inlinereidentify.masking.tokenization.key.DataEncryptionKeySource;
import com.inlinereidentify.masking.tokenization.spi.CryptoProvider;
import com.inlinereidentify.masking.tokenization.spi.CryptoProviderRegistry;
import com.inlinereidentify.masking.tokenization.spi.TokenizationScheme;
import com.inlinereidentify.masking.tokenization.spi.TokenizationSchemeRegistry;

/**
 * Entry point for a Redshift <a
 * href="https://docs.aws.amazon.com/redshift/latest/dg/udf-creating-a-lambda-sql-udf.html">Lambda
 * UDF</a>. Redshift invokes the function directly (not through API Gateway) with a fixed request
 * shape and expects a matching response shape back; this handler implements that contract and
 * nothing else, so it is deployed unchanged to both AWS Lambda and the local docker-compose RIE
 * container used for development against a local Postgres stand-in database.
 *
 * <p>This is one of two ways to reach the tokenize/detokenize core (see {@link BatchTokenizer}):
 * the other is {@link com.inlinereidentify.masking.tokenization.http.TokenizationHttpServer}, a
 * plain REST API for databases/tools that aren't Redshift and can't invoke a Lambda directly.
 * Both parse their own wire format into a list of values and hand it to {@link BatchTokenizer},
 * so the two can't drift on null-handling or failure accounting.
 *
 * <p>Request:
 * <pre>{@code
 * {
 *   "request_id": "...", "cluster": "...", "user": "...", "database": "...",
 *   "external_function": "tokenize", "query_id": 123, "num_records": 2,
 *   "arguments": [["plaintext row 1"], ["plaintext row 2"]]
 * }
 * }</pre>
 *
 * <p>Response:
 * <pre>{@code
 * { "success": true, "num_records": 2, "results": ["token1", "token2"] }
 * }</pre>
 *
 * <p>Direction (tokenize vs. reidentify) is selected by the {@code UDF_OPERATION} environment
 * variable, not by request content: the same jar is deployed as two separate Lambda functions
 * (one per Redshift external function) with different environment configuration, which keeps the
 * request/response contract identical between them and lets Redshift's per-function IAM/logging
 * separate the two operations.
 *
 * <p>The crypto provider and cipher algorithm are likewise environment-driven -- {@code
 * CRYPTO_PROVIDER} (default {@code "BCFIPS"}) and {@code CIPHER_ALGORITHM} (default {@code
 * "AES-CBC-CTS"}) -- and resolved via the same {@code
 * com.inlinereidentify.masking.tokenization.spi} registries the Delphix plugin uses, so the two
 * entry points can never disagree on how a token is produced/reversed for a given configuration.
 */
public class RedshiftUdfHandler implements RequestHandler<Map<String, Object>, Map<String, Object>> {

    private enum Operation { TOKENIZE, REIDENTIFY }

    private final Operation operation;
    private final byte[] dataEncryptionKey;
    private final TokenizationScheme scheme;

    /** Invoked once per execution environment; Lambda reuses this instance across warm invocations. */
    public RedshiftUdfHandler() {
        this.operation = Operation.valueOf(
                System.getenv().getOrDefault("UDF_OPERATION", "TOKENIZE").toUpperCase(Locale.ROOT));
        this.dataEncryptionKey = DataEncryptionKeySource.resolve();
        CryptoProvider provider = CryptoProviderRegistry.resolve(
                System.getenv().getOrDefault("CRYPTO_PROVIDER", "BCFIPS"));
        this.scheme = TokenizationSchemeRegistry.resolve(
                System.getenv().getOrDefault("CIPHER_ALGORITHM", "AES-CBC-CTS"), provider);
    }

    @Override
    public Map<String, Object> handleRequest(Map<String, Object> input, Context context) {
        @SuppressWarnings("unchecked")
        List<List<Object>> arguments = (List<List<Object>>) input.get("arguments");
        int numRecords = ((Number) input.get("num_records")).intValue();

        List<String> values = new ArrayList<>(arguments.size());
        for (List<Object> row : arguments) {
            values.add(row.isEmpty() ? null : (String) row.get(0));
        }

        BatchTokenizer.Result result = BatchTokenizer.apply(
                values, operation == Operation.TOKENIZE, scheme, dataEncryptionKey,
                (index, e) -> {
                    StringWriter trace = new StringWriter();
                    e.printStackTrace(new PrintWriter(trace));
                    context.getLogger().log("Row " + index + " failed: " + trace);
                });

        Map<String, Object> response = new HashMap<>();
        // Partial failures (bad individual token/value) leave that row NULL rather than
        // failing the whole batch; only report success=false when every row failed, which
        // signals a systemic problem (e.g. wrong key) rather than a handful of bad rows.
        response.put("success", result.failureCount < values.size());
        response.put("num_records", numRecords);
        response.put("results", result.results);
        if (result.failureCount > 0) {
            response.put("error_msg", result.failureCount + " of " + values.size() + " rows failed; see function logs");
        }
        return response;
    }
}
