/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingScheme;
import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingSchemeFactory;

/**
 * Built-in {@code "CREDIT-CARD-MASK"} algorithm: masks a card number the same way {@code
 * SEGMENT-MAPPING} does (4-digit segments substituted from a keyed, shuffled lookup table), but
 * tolerates {@code -}/space separators -- they're stripped before substitution and reinserted at
 * their original positions afterward, so {@code "4111-1111-1111-1111"} stays formatted like a
 * card number instead of requiring callers to strip/reformat it themselves. Deterministic per
 * key, not reversible (see {@link DigitSegmentSubstitution}). Characters other than digits,
 * {@code -}, and space are rejected, as is a value with no digits at all.
 */
public final class CreditCardMaskSchemeFactory implements OneWayMaskingSchemeFactory {

    @Override
    public String id() {
        return "CREDIT-CARD-MASK";
    }

    @Override
    public OneWayMaskingScheme create() {
        return new CreditCardMaskScheme();
    }

    private static final class CreditCardMaskScheme implements OneWayMaskingScheme {

        private static final int LENGTH_LIMIT = 64;

        private final DigitSegmentSubstitution substitution = new DigitSegmentSubstitution("CREDIT-CARD-MASK");

        @Override
        public String mask(String value, byte[] key) {
            if (value == null) {
                return null;
            }
            if (value.isEmpty()) {
                return value;
            }
            KeyedLookup.requireNonEmptyKey(key);
            if (value.length() > LENGTH_LIMIT) {
                throw new OneWayMaskingException("Input longer than " + LENGTH_LIMIT + " characters");
            }

            StringBuilder digits = new StringBuilder(value.length());
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                if (Character.isDigit(c)) {
                    digits.append(c);
                } else if (c != '-' && c != ' ') {
                    throw new OneWayMaskingException(
                            "Unsupported character at index " + i + " (expected digits, '-', or space)");
                }
            }
            if (digits.length() == 0) {
                throw new OneWayMaskingException("No digits found in input");
            }

            String maskedDigits = substitution.substitute(digits.toString(), key);

            StringBuilder result = new StringBuilder(value.length());
            int digitIndex = 0;
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                result.append(Character.isDigit(c) ? maskedDigits.charAt(digitIndex++) : c);
            }
            return result.toString();
        }
    }
}
