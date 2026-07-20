/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingScheme;

/**
 * Wire-format-agnostic batch one-way-masking core, mirroring {@code
 * com.delphix.dynamicmasking.tokenization.BatchTokenizer}'s per-row null-handling and failure
 * accounting, but for a single mask-only direction (there's no reidentify counterpart for these
 * schemes). Shared by every standalone entry point (the Redshift Lambda UDF handler, the plain
 * HTTP API) so they can't drift on how a failed row is reported.
 */
public final class BatchMasker {

    private BatchMasker() {}

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
    public static Result apply(List<String> values, OneWayMaskingScheme scheme, byte[] key,
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
                results.add(scheme.mask(value, key));
                errors.add(null);
            } catch (RuntimeException e) {
                if (onRowFailure != null) {
                    onRowFailure.accept(i, e);
                }
                results.add(null);
                // Deliberately doesn't include the raw input in the message (would leak it to
                // logs/API responses).
                errors.add("Failed to mask value: " + e.getMessage());
                failures++;
            }
        }
        return new Result(results, failures, errors);
    }
}
