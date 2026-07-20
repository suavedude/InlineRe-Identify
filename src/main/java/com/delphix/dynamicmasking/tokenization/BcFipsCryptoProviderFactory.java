/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.tokenization;

import com.delphix.dynamicmasking.tokenization.spi.CryptoProvider;
import com.delphix.dynamicmasking.tokenization.spi.CryptoProviderFactory;

/** Built-in {@code "BCFIPS"} provider (Bouncy Castle FIPS, approved-only mode). Default. */
public final class BcFipsCryptoProviderFactory implements CryptoProviderFactory {

    @Override
    public String id() {
        return "BCFIPS";
    }

    @Override
    public CryptoProvider create() {
        return new CryptoProvider() {
            @Override
            public String name() {
                return FipsProvider.NAME;
            }

            @Override
            public void ensureRegistered() {
                FipsProvider.ensureRegistered();
            }
        };
    }
}
