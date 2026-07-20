/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

import java.util.List;

import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingScheme;
import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingSchemeFactory;

/**
 * Built-in {@code "FULL-NAME-MASK"} algorithm: masks a "First Last" (or "First Middle Last", ...)
 * value token-by-token -- the first whitespace-separated token is replaced from the bundled
 * first-name list, every subsequent token from the bundled last-name list -- rather than
 * collapsing the whole value to a single replacement the way {@link FirstNameLookupSchemeFactory}
 * does. {@code "Jane Doe"} becomes something like {@code "Dorothy Ramirez"}: a realistic-looking
 * full name, not just one word. Deterministic per key (same token + same key always maps to the
 * same replacement), not reversible.
 */
public final class FullNameMaskSchemeFactory implements OneWayMaskingSchemeFactory {

    @Override
    public String id() {
        return "FULL-NAME-MASK";
    }

    @Override
    public OneWayMaskingScheme create() {
        return new FullNameMaskScheme();
    }

    private static final class FullNameMaskScheme implements OneWayMaskingScheme {

        private static final String FIRST_SALT = "FULL-NAME-MASK:first";
        private static final String LAST_SALT = "FULL-NAME-MASK:last";

        private final List<String> firstNames = NameListLoader.load("first-names.txt");
        private final List<String> lastNames = NameListLoader.load("last-names.txt");

        @Override
        public String mask(String value, byte[] key) {
            if (value == null) {
                return null;
            }
            String trimmed = value.trim();
            if (trimmed.isEmpty()) {
                return value;
            }
            KeyedLookup.requireNonEmptyKey(key);

            String[] tokens = trimmed.split("\\s+");
            StringBuilder result = new StringBuilder(value.length());
            for (int i = 0; i < tokens.length; i++) {
                if (i > 0) {
                    result.append(' ');
                }
                boolean isFirstToken = (i == 0);
                List<String> list = isFirstToken ? firstNames : lastNames;
                String salt = isFirstToken ? FIRST_SALT : LAST_SALT;
                int index = KeyedLookup.index(key, salt, tokens[i], list.size());
                result.append(list.get(index));
            }
            return result.toString();
        }
    }
}
