/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking.spi;

import java.util.ServiceLoader;
import java.util.TreeSet;

/** Resolves a {@code maskingScheme} config value to a registered {@link OneWayMaskingSchemeFactory}. */
public final class OneWayMaskingSchemeRegistry {

    private OneWayMaskingSchemeRegistry() {}

    public static OneWayMaskingScheme resolve(String id) {
        for (OneWayMaskingSchemeFactory factory : loader()) {
            if (factory.id().equalsIgnoreCase(id)) {
                return factory.create();
            }
        }
        throw new IllegalArgumentException(
                "Unknown masking scheme '" + id + "'. Known schemes: " + knownIds());
    }

    public static TreeSet<String> knownIds() {
        TreeSet<String> ids = new TreeSet<>();
        for (OneWayMaskingSchemeFactory factory : loader()) {
            ids.add(factory.id());
        }
        return ids;
    }

    private static ServiceLoader<OneWayMaskingSchemeFactory> loader() {
        return ServiceLoader.load(OneWayMaskingSchemeFactory.class, OneWayMaskingSchemeRegistry.class.getClassLoader());
    }
}
