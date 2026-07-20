/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.tokenization;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;

import com.delphix.dynamicmasking.tokenization.spi.CryptoProvider;
import com.delphix.dynamicmasking.tokenization.spi.CryptoProviderRegistry;
import com.delphix.dynamicmasking.tokenization.spi.TokenizationScheme;
import com.delphix.dynamicmasking.tokenization.spi.TokenizationSchemeRegistry;

import org.junit.jupiter.api.Test;

class AesEcbSchemeFactoryTest {

    private static byte[] randomKey(int length) {
        byte[] dek = new byte[length];
        new SecureRandom().nextBytes(dek);
        return dek;
    }

    private static TokenizationScheme scheme() {
        CryptoProvider provider = CryptoProviderRegistry.resolve("BCFIPS");
        return TokenizationSchemeRegistry.resolve("AES-ECB", provider);
    }

    @Test
    void registeredUnderKnownIds() {
        assertEquals(true, TokenizationSchemeRegistry.knownIds().contains("AES-ECB"));
    }

    @Test
    void roundTripsShortAndLongValues() {
        TokenizationScheme scheme = scheme();
        byte[] dek = randomKey(16);

        for (String value : new String[] {"abc", "4111-1111-1111-1111", ""}) {
            String token = scheme.tokenize(value, dek);
            assertEquals(value, scheme.detokenize(token, dek));
        }
    }

    @Test
    void sameInputProducesSameToken() {
        TokenizationScheme scheme = scheme();
        byte[] dek = randomKey(16);
        assertEquals(scheme.tokenize("repeat-this-value", dek), scheme.tokenize("repeat-this-value", dek));
    }

    @Test
    void differentInputsProduceDifferentTokens() {
        TokenizationScheme scheme = scheme();
        byte[] dek = randomKey(16);
        assertNotEquals(scheme.tokenize("value-one", dek), scheme.tokenize("value-two", dek));
    }

    @Test
    void nullValuePassesThroughUnchanged() {
        TokenizationScheme scheme = scheme();
        byte[] dek = randomKey(16);
        assertNull(scheme.tokenize(null, dek));
        assertNull(scheme.detokenize(null, dek));
    }

    @Test
    void wrongKeyLengthThrows() {
        TokenizationScheme scheme = scheme();
        assertThrows(RuntimeException.class, () -> scheme.tokenize("value", new byte[8]));
    }
}
