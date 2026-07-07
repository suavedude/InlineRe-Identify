/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.inlinereidentify.masking.tokenization.spi;

/**
 * A registered JCE security provider (e.g. BC-FIPS, SunJCE, a PKCS#11/HSM bridge) that a {@link
 * TokenizationScheme} performs {@code Cipher.getInstance(transformation, name())} against.
 * Obtained from {@link CryptoProviderRegistry}, never constructed directly.
 */
public interface CryptoProvider {

    /** The JCE provider name to pass to {@code Cipher.getInstance(transformation, name)}. */
    String name();

    /**
     * Registers the provider with the JVM's {@link java.security.Security} if it isn't already
     * (e.g. {@code Security.addProvider(...)}). Must be idempotent and safe to call from
     * multiple threads/instances -- {@link CryptoProviderRegistry#resolve} calls this on every
     * resolution, and callers may resolve the same provider id repeatedly across the life of a
     * process (e.g. once per masking job, once per Lambda cold start).
     */
    void ensureRegistered();
}
