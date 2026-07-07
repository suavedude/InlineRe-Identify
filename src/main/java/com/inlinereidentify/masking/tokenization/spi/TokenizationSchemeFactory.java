/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.inlinereidentify.masking.tokenization.spi;

/**
 * Extension point for adding a new tokenization algorithm without touching this module's
 * source: drop a jar on the classpath containing an implementation of this interface plus a
 * {@code META-INF/services/com.inlinereidentify.masking.tokenization.spi.TokenizationSchemeFactory}
 * file naming it (standard {@link java.util.ServiceLoader} discovery), and it becomes selectable
 * via the {@code cipherAlgorithm} plugin config field / {@code CIPHER_ALGORITHM} Lambda env var.
 *
 * <p>Implementations must have a public no-arg constructor.
 */
public interface TokenizationSchemeFactory {

    /** Selector string matched case-insensitively against config, e.g. {@code "AES-CBC-CTS"}. */
    String id();

    TokenizationScheme create(CryptoProvider provider);
}
