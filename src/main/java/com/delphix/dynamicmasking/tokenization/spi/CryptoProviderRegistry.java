/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.tokenization.spi;

import java.util.ServiceLoader;
import java.util.TreeSet;

/** Resolves a {@code cryptoProvider} config value to a registered {@link CryptoProviderFactory}. */
public final class CryptoProviderRegistry {

    private CryptoProviderRegistry() {}

    /** Resolves {@code id} and ensures the provider is registered with the JVM before returning it. */
    public static CryptoProvider resolve(String id) {
        for (CryptoProviderFactory factory : loader()) {
            if (factory.id().equalsIgnoreCase(id)) {
                CryptoProvider provider = factory.create();
                provider.ensureRegistered();
                return provider;
            }
        }
        throw new IllegalArgumentException(
                "Unknown crypto provider '" + id + "'. Known providers: " + knownIds());
    }

    public static TreeSet<String> knownIds() {
        TreeSet<String> ids = new TreeSet<>();
        for (CryptoProviderFactory factory : loader()) {
            ids.add(factory.id());
        }
        return ids;
    }

    private static ServiceLoader<CryptoProviderFactory> loader() {
        // Loaded against this class's own classloader rather than the thread context
        // classloader: plugin hosts (Delphix's PluginFirstClassLoader, AWS Lambda's runtime)
        // don't reliably set the context classloader to something that can see this jar's
        // META-INF/services entries.
        return ServiceLoader.load(CryptoProviderFactory.class, CryptoProviderRegistry.class.getClassLoader());
    }
}
