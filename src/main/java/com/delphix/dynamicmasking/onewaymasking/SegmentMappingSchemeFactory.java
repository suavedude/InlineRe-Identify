/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingScheme;
import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingSchemeFactory;

/**
 * Built-in {@code "SEGMENT-MAPPING"} algorithm: masks a digit string by breaking it into
 * fixed-size 4-digit segments and substituting each segment from a keyed, shuffled lookup table
 * for that segment position. Deterministic per key (referential integrity preserved: same input
 * segment + same key always maps to the same replacement segment), but not reversible since the
 * substitution tables live only in memory, keyed off the DEK, and are never exposed. Input must
 * be digits only (no separators); non-digit characters or inputs over 256 characters throw -- see
 * {@link CreditCardMaskSchemeFactory} for a format-preserving variant that tolerates separators.
 */
public final class SegmentMappingSchemeFactory implements OneWayMaskingSchemeFactory {

    @Override
    public String id() {
        return "SEGMENT-MAPPING";
    }

    @Override
    public OneWayMaskingScheme create() {
        return new SegmentMappingScheme();
    }

    private static final class SegmentMappingScheme implements OneWayMaskingScheme {

        private static final int LENGTH_LIMIT = 256;

        private final DigitSegmentSubstitution substitution = new DigitSegmentSubstitution("SEGMENT-MAPPING");

        @Override
        public String mask(String value, byte[] key) {
            if (value == null) {
                return null;
            }
            KeyedLookup.requireNonEmptyKey(key);
            if (value.length() > LENGTH_LIMIT) {
                throw new OneWayMaskingException("Input longer than " + LENGTH_LIMIT + " characters");
            }
            for (int i = 0; i < value.length(); i++) {
                if (!Character.isDigit(value.charAt(i))) {
                    throw new OneWayMaskingException("Non-digit character encountered at index " + i);
                }
            }
            return substitution.substitute(value, key);
        }
    }
}
