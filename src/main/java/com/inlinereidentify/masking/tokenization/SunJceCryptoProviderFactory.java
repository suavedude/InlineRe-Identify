/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.inlinereidentify.masking.tokenization;

import com.inlinereidentify.masking.tokenization.spi.CryptoProvider;
import com.inlinereidentify.masking.tokenization.spi.CryptoProviderFactory;

/**
 * Built-in {@code "SunJCE"} provider: the JDK's bundled, non-FIPS-validated provider. Needs no
 * registration (every JVM ships it) and no extra dependency, unlike BC-FIPS -- useful for
 * environments without a FIPS requirement, or for isolating whether a problem is BC-FIPS-specific.
 */
public final class SunJceCryptoProviderFactory implements CryptoProviderFactory {

    @Override
    public String id() {
        return "SunJCE";
    }

    @Override
    public CryptoProvider create() {
        return new CryptoProvider() {
            @Override
            public String name() {
                return "SunJCE";
            }

            @Override
            public void ensureRegistered() {
                // Bundled with every JVM; nothing to register.
            }
        };
    }
}
