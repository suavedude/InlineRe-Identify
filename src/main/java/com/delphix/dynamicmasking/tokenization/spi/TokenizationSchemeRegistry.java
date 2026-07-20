/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.tokenization.spi;

import java.util.ServiceLoader;
import java.util.TreeSet;

/** Resolves a {@code cipherAlgorithm} config value to a registered {@link TokenizationSchemeFactory}. */
public final class TokenizationSchemeRegistry {

    private TokenizationSchemeRegistry() {}

    public static TokenizationScheme resolve(String id, CryptoProvider provider) {
        for (TokenizationSchemeFactory factory : loader()) {
            if (factory.id().equalsIgnoreCase(id)) {
                return factory.create(provider);
            }
        }
        throw new IllegalArgumentException(
                "Unknown cipher algorithm '" + id + "'. Known algorithms: " + knownIds());
    }

    public static TreeSet<String> knownIds() {
        TreeSet<String> ids = new TreeSet<>();
        for (TokenizationSchemeFactory factory : loader()) {
            ids.add(factory.id());
        }
        return ids;
    }

    private static ServiceLoader<TokenizationSchemeFactory> loader() {
        return ServiceLoader.load(TokenizationSchemeFactory.class, TokenizationSchemeRegistry.class.getClassLoader());
    }
}
