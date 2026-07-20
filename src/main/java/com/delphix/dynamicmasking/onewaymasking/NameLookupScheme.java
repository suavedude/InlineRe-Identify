/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

import java.util.List;

import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingScheme;

/**
 * Deterministically replaces a value with one of a bundled list of names, selected by a keyed
 * hash of the input value. Same input + same key always yields the same replacement name
 * (referential integrity across rows), but the mapping can't be reversed: many distinct inputs
 * share each output name, so there's no way back from a name to the original value.
 */
final class NameLookupScheme implements OneWayMaskingScheme {

    private final List<String> names;
    private final String salt;

    NameLookupScheme(String resourceName, String salt) {
        this.names = NameListLoader.load(resourceName);
        this.salt = salt;
    }

    @Override
    public String mask(String value, byte[] key) {
        if (value == null) {
            return null;
        }
        if (value.isEmpty()) {
            return value;
        }
        KeyedLookup.requireNonEmptyKey(key);
        int index = KeyedLookup.index(key, salt, value, names.size());
        return names.get(index);
    }
}
