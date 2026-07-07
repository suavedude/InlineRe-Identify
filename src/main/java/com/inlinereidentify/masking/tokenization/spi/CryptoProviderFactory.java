/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.inlinereidentify.masking.tokenization.spi;

/**
 * Extension point for adding a new crypto provider without touching this module's source: drop
 * a jar on the classpath containing an implementation of this interface plus a {@code
 * META-INF/services/com.inlinereidentify.masking.tokenization.spi.CryptoProviderFactory} file
 * naming it (standard {@link java.util.ServiceLoader} discovery), and it becomes selectable via
 * the {@code cryptoProvider} plugin config field / {@code CRYPTO_PROVIDER} Lambda env var.
 *
 * <p>Implementations must have a public no-arg constructor.
 */
public interface CryptoProviderFactory {

    /** Selector string matched case-insensitively against config, e.g. {@code "BCFIPS"}. */
    String id();

    CryptoProvider create();
}
