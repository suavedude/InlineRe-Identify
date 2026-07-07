/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.inlinereidentify.masking.tokenization;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import java.security.Security;

/**
 * Registers the BC-FIPS ("BCFIPS") security provider used by {@link TokenCipher} and {@link
 * ShortValueCipher}. Both ciphers must call {@link #ensureRegistered()} themselves rather than
 * relying on the other's class-init: referencing another class's {@code static final int}
 * constant (e.g. {@code TokenCipher.BLOCK_LEN}) is inlined by javac and does <em>not</em>
 * trigger that class's static initializer, so a fresh JVM that tokenizes a short value first
 * (the only case that touches {@link ShortValueCipher}) would otherwise never run {@link
 * TokenCipher}'s provider-registration block and fail with {@code NoSuchProviderException}.
 */
final class FipsProvider {

    static final String NAME = "BCFIPS";

    private FipsProvider() {}

    static synchronized void ensureRegistered() {
        if (Security.getProvider(NAME) == null) {
            Security.addProvider(new BouncyCastleFipsProvider());
        }
        if (!CryptoServicesRegistrar.isInApprovedOnlyMode()) {
            // Thread-local in BC-FIPS; set on every thread that performs crypto.
            CryptoServicesRegistrar.setApprovedOnlyMode(true);
        }
    }
}
