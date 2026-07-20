/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking.spi;

/**
 * A one-way (non-reversible) masking algorithm, keyed for determinism. Unlike {@link
 * com.delphix.dynamicmasking.tokenization.spi.TokenizationScheme}, there is deliberately no
 * {@code unmask}/{@code detokenize} counterpart: schemes in this family (name/date/segment
 * lookups, static redaction) replace a value with a realistic-looking substitute drawn from a
 * space much smaller than the original value space, so the mapping cannot be inverted even in
 * principle. The same (value, key) pair always produces the same output, which preserves
 * referential integrity across rows/tables the same way the deterministic tokenization schemes
 * do, without needing to keep the original value recoverable.
 */
public interface OneWayMaskingScheme {

    /** @return null if {@code value} is null; otherwise a one-way masked replacement. */
    String mask(String value, byte[] key);
}
