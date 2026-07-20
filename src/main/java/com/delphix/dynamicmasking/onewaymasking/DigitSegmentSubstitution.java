/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Shared substitution core for schemes that mask a digit string by breaking it into fixed-size
 * 4-digit segments and replacing each with a value from a keyed, shuffled lookup table for that
 * segment position. Used by {@link SegmentMappingSchemeFactory} (generic, digits-only) and {@link
 * CreditCardMaskSchemeFactory} (format-preserving, tolerates separators) -- each instance is
 * namespaced by a {@code salt} so the two never share a substitution table even under the same
 * key.
 */
final class DigitSegmentSubstitution {

    private static final int SEGMENT_SIZE = 4;
    private static final int SEGMENT_VALUE_COUNT = 10_000; // "0000".."9999"
    private static final String VALUE_FORMAT = "%0" + SEGMENT_SIZE + "d";

    private final String salt;
    // Keyed by (DEK, segment position) since the shuffle depends on the key; cheap to keep
    // around for the life of the process (one process normally uses exactly one key).
    private final ConcurrentHashMap<String, List<String>> segmentTables = new ConcurrentHashMap<>();

    DigitSegmentSubstitution(String salt) {
        this.salt = salt;
    }

    /** @param digits digits only, no separators -- callers strip/reinsert their own formatting. */
    String substitute(String digits, byte[] key) {
        StringBuilder result = new StringBuilder(digits.length());
        int segment = 0;
        int lookup = 0;

        for (int i = 0; i < digits.length(); i++) {
            lookup = lookup * 10 + Character.digit(digits.charAt(i), 10);
            if (i % SEGMENT_SIZE == SEGMENT_SIZE - 1) {
                result.append(segmentTable(key, segment).get(lookup));
                lookup = 0;
                segment++;
            }
        }

        int remainder = digits.length() % SEGMENT_SIZE;
        if (remainder > 0) {
            result.append(segmentTable(key, segment).get(lookup).substring(0, remainder));
        }
        return result.toString();
    }

    private List<String> segmentTable(byte[] key, int segment) {
        String cacheKey = Base64.getEncoder().encodeToString(key) + ":" + segment;
        return segmentTables.computeIfAbsent(cacheKey, k -> {
            List<String> table = new ArrayList<>(SEGMENT_VALUE_COUNT);
            for (int i = 0; i < SEGMENT_VALUE_COUNT; i++) {
                table.add(String.format(VALUE_FORMAT, i));
            }
            KeyedLookup.shuffle(key, salt + ":" + segment, table);
            return table;
        });
    }
}
