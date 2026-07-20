/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.tokenization.spi;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;

import org.junit.jupiter.api.Test;

class TokenizationSchemeRegistryTest {

    @Test
    void resolvesBuiltInAlgorithmCaseInsensitively() {
        CryptoProvider provider = CryptoProviderRegistry.resolve("BCFIPS");
        assertNotNull(TokenizationSchemeRegistry.resolve("aes-cbc-cts", provider));
    }

    @Test
    void knownIdsIncludesBuiltIn() {
        assertTrue(TokenizationSchemeRegistry.knownIds().contains("AES-CBC-CTS"));
    }

    @Test
    void unknownAlgorithmIdThrowsWithKnownIdsListed() {
        CryptoProvider provider = CryptoProviderRegistry.resolve("BCFIPS");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> TokenizationSchemeRegistry.resolve("NoSuchAlgorithm", provider));
        assertTrue(e.getMessage().contains("NoSuchAlgorithm"));
        assertTrue(e.getMessage().contains("AES-CBC-CTS"));
    }

    @Test
    void resolvedSchemeRoundTrips() {
        CryptoProvider provider = CryptoProviderRegistry.resolve("BCFIPS");
        TokenizationScheme scheme = TokenizationSchemeRegistry.resolve("AES-CBC-CTS", provider);

        byte[] dek = new byte[16];
        new SecureRandom().nextBytes(dek);

        String token = scheme.tokenize("hello world", dek);
        assertEquals("hello world", scheme.detokenize(token, dek));
    }
}
