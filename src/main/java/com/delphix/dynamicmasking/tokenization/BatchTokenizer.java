/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.tokenization;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

import com.delphix.dynamicmasking.tokenization.spi.TokenizationScheme;

/**
 * Wire-format-agnostic batch tokenize/detokenize core, shared by every standalone entry point
 * (the Redshift Lambda UDF handler, the plain HTTP API, and any future adapter for another
 * database's remote-function contract). Each entry point owns parsing its own platform-specific
 * request into a {@code List<String>} (nulls allowed, pass through unchanged) and serializing
 * the result back into its own response shape; this class owns the one thing that must not
 * drift between them: per-row null-handling and failure accounting.
 *
 * <p>A failed row never fails the whole batch -- it comes back {@code null} in {@link
 * Result#results}, and {@link Result#failureCount} tells the caller how many rows failed so it
 * can decide how to report that (e.g. Redshift's {@code error_msg}, an HTTP response field).
 */
public final class BatchTokenizer {

    private BatchTokenizer() {}

    public static final class Result {
        public final List<String> results;
        public final int failureCount;
        /** Parallel to {@link #results}: null for a successful/null row, an explanatory message otherwise. */
        public final List<String> errors;

        private Result(List<String> results, int failureCount, List<String> errors) {
            this.results = results;
            this.failureCount = failureCount;
            this.errors = errors;
        }
    }

    /**
     * @param onRowFailure optional (may be null); called with (index, exception) for each failed
     *            row, e.g. to log it with entry-point-specific context.
     */
    public static Result apply(List<String> values, boolean tokenize, TokenizationScheme scheme, byte[] key,
            BiConsumer<Integer, RuntimeException> onRowFailure) {
        List<String> results = new ArrayList<>(values.size());
        List<String> errors = new ArrayList<>(values.size());
        int failures = 0;
        for (int i = 0; i < values.size(); i++) {
            String value = values.get(i);
            if (value == null) {
                results.add(null);
                errors.add(null);
                continue;
            }
            try {
                results.add(tokenize ? scheme.tokenize(value, key) : scheme.detokenize(value, key));
                errors.add(null);
            } catch (RuntimeException e) {
                if (onRowFailure != null) {
                    onRowFailure.accept(i, e);
                }
                results.add(null);
                // Deliberately doesn't include the raw input in the message (would leak it to
                // logs/API responses); e.getMessage() from TokenCipher/ShortValueCipher already
                // avoids that. Framed around "corrupted" for reidentify specifically, since a
                // detokenize failure here almost always means a malformed/tampered/foreign token
                // rather than a transient error -- there's no other way for it to fail.
                errors.add(tokenize
                        ? "Failed to tokenize value: " + e.getMessage()
                        : "Failed to reidentify token: value appears corrupted, malformed, or was not "
                                + "produced under the configured key/algorithm (" + e.getMessage() + ")");
                failures++;
            }
        }
        return new Result(results, failures, errors);
    }
}
