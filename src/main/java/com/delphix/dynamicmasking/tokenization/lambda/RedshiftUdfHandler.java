/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.tokenization.lambda;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.delphix.dynamicmasking.onewaymasking.BatchMasker;
import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingScheme;
import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingSchemeRegistry;
import com.delphix.dynamicmasking.tokenization.BatchTokenizer;
import com.delphix.dynamicmasking.tokenization.key.DataEncryptionKeySource;
import com.delphix.dynamicmasking.tokenization.spi.CryptoProvider;
import com.delphix.dynamicmasking.tokenization.spi.CryptoProviderRegistry;
import com.delphix.dynamicmasking.tokenization.spi.TokenizationScheme;
import com.delphix.dynamicmasking.tokenization.spi.TokenizationSchemeRegistry;

/**
 * Entry point for a Redshift <a
 * href="https://docs.aws.amazon.com/redshift/latest/dg/udf-creating-a-lambda-sql-udf.html">Lambda
 * UDF</a>. Redshift invokes the function directly (not through API Gateway) with a fixed request
 * shape and expects a matching response shape back; this handler implements that contract and
 * nothing else, so it is deployed unchanged to both AWS Lambda and the local docker-compose RIE
 * container used for development against a local Postgres stand-in database.
 *
 * <p>This is one of two ways to reach the tokenize/detokenize core (see {@link BatchTokenizer}):
 * the other is {@link com.delphix.dynamicmasking.tokenization.http.TokenizationHttpServer}, a
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
 * <p>Direction/operation is selected by the {@code UDF_OPERATION} environment variable (see
 * {@link Operation} for the full list), not by request content: the same jar is deployed as one
 * separate Lambda function per Redshift external function, each with different environment
 * configuration, which keeps the request/response contract identical across them and lets
 * Redshift's per-function IAM/logging separate the operations.
 *
 * <p>For {@code TOKENIZE}/{@code REIDENTIFY}, the crypto provider and cipher algorithm are
 * environment-driven -- {@code CRYPTO_PROVIDER} (default {@code "BCFIPS"}) and {@code
 * CIPHER_ALGORITHM} (default {@code "AES-CBC-CTS"}) -- and resolved via the same {@code
 * com.delphix.dynamicmasking.tokenization.spi} registries the Delphix plugin uses, so the two
 * entry points can never disagree on how a token is produced/reversed for a given configuration.
 *
 * <p>Every {@code MASK_*} operation is permanently fixed to one one-way scheme (see {@link
 * #MASK_SCHEME_BY_OPERATION}, resolved via {@code
 * com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingSchemeRegistry}) rather than a
 * scheme-selector env var -- one Lambda function per data shape, so a function deployed for
 * credit card numbers can't accidentally be pointed at email addresses. None have a reverse
 * direction.
 */
public class RedshiftUdfHandler implements RequestHandler<Map<String, Object>, Map<String, Object>> {

    private enum Operation {
        TOKENIZE, REIDENTIFY,
        MASK_FULL_NAME, MASK_CREDIT_CARD, MASK_EMAIL,
        MASK_FIRST_NAME, MASK_LAST_NAME, MASK_DATE_SHIFT, MASK_SEGMENT_MAPPING
    }

    /**
     * {@code MASK_*} operation -> the scheme id it's permanently fixed to. Adding a new
     * fixed-scheme operation is exactly one enum constant plus one entry here.
     */
    private static final Map<Operation, String> MASK_SCHEME_BY_OPERATION = new EnumMap<>(Operation.class);

    static {
        MASK_SCHEME_BY_OPERATION.put(Operation.MASK_FULL_NAME, "FULL-NAME-MASK");
        MASK_SCHEME_BY_OPERATION.put(Operation.MASK_CREDIT_CARD, "CREDIT-CARD-MASK");
        MASK_SCHEME_BY_OPERATION.put(Operation.MASK_EMAIL, "EMAIL-MASK");
        MASK_SCHEME_BY_OPERATION.put(Operation.MASK_FIRST_NAME, "FIRST-NAME-LOOKUP");
        MASK_SCHEME_BY_OPERATION.put(Operation.MASK_LAST_NAME, "LAST-NAME-LOOKUP");
        MASK_SCHEME_BY_OPERATION.put(Operation.MASK_DATE_SHIFT, "DATE-SHIFT");
        MASK_SCHEME_BY_OPERATION.put(Operation.MASK_SEGMENT_MAPPING, "SEGMENT-MAPPING");
    }

    private final Operation operation;
    private final byte[] dataEncryptionKey;
    /** Null unless {@link #operation} is {@code TOKENIZE} or {@code REIDENTIFY}. */
    private final TokenizationScheme scheme;
    /** Null unless {@link #operation} is one of the {@code MASK_*} operations. */
    private final OneWayMaskingScheme maskingScheme;

    /** Invoked once per execution environment; Lambda reuses this instance across warm invocations. */
    public RedshiftUdfHandler() {
        this.operation = Operation.valueOf(
                System.getenv().getOrDefault("UDF_OPERATION", "TOKENIZE").toUpperCase(Locale.ROOT));
        this.dataEncryptionKey = DataEncryptionKeySource.resolve();

        String maskingSchemeId = MASK_SCHEME_BY_OPERATION.get(operation);
        if (maskingSchemeId != null) {
            this.maskingScheme = OneWayMaskingSchemeRegistry.resolve(maskingSchemeId);
            this.scheme = null;
        } else {
            CryptoProvider provider = CryptoProviderRegistry.resolve(
                    System.getenv().getOrDefault("CRYPTO_PROVIDER", "BCFIPS"));
            this.scheme = TokenizationSchemeRegistry.resolve(
                    System.getenv().getOrDefault("CIPHER_ALGORITHM", "AES-CBC-CTS"), provider);
            this.maskingScheme = null;
        }
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

        int failureCount;
        List<String> results;
        if (maskingScheme != null) {
            BatchMasker.Result result = BatchMasker.apply(
                    values, maskingScheme, dataEncryptionKey,
                    (index, e) -> logRowFailure(context, index, e));
            results = result.results;
            failureCount = result.failureCount;
        } else {
            BatchTokenizer.Result result = BatchTokenizer.apply(
                    values, operation == Operation.TOKENIZE, scheme, dataEncryptionKey,
                    (index, e) -> logRowFailure(context, index, e));
            results = result.results;
            failureCount = result.failureCount;
        }

        Map<String, Object> response = new HashMap<>();
        // Partial failures (bad individual token/value) leave that row NULL rather than
        // failing the whole batch; only report success=false when every row failed, which
        // signals a systemic problem (e.g. wrong key) rather than a handful of bad rows.
        response.put("success", failureCount < values.size());
        response.put("num_records", numRecords);
        response.put("results", results);
        if (failureCount > 0) {
            response.put("error_msg", failureCount + " of " + values.size() + " rows failed; see function logs");
        }
        return response;
    }

    private static void logRowFailure(Context context, int index, RuntimeException e) {
        StringWriter trace = new StringWriter();
        e.printStackTrace(new PrintWriter(trace));
        context.getLogger().log("Row " + index + " failed: " + trace);
    }
}
