/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.tokenization.spi;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class CryptoProviderRegistryTest {

    @Test
    void resolvesBuiltInProvidersCaseInsensitively() {
        assertEquals("BCFIPS", CryptoProviderRegistry.resolve("bcfips").name());
        assertEquals("SunJCE", CryptoProviderRegistry.resolve("SUNJCE").name());
    }

    @Test
    void knownIdsIncludesBuiltIns() {
        assertTrue(CryptoProviderRegistry.knownIds().contains("BCFIPS"));
        assertTrue(CryptoProviderRegistry.knownIds().contains("SunJCE"));
    }

    @Test
    void unknownProviderIdThrowsWithKnownIdsListed() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> CryptoProviderRegistry.resolve("NoSuchProvider"));
        assertTrue(e.getMessage().contains("NoSuchProvider"));
        assertTrue(e.getMessage().contains("BCFIPS"));
    }
}
