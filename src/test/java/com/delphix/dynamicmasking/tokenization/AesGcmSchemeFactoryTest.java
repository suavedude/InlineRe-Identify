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

class AesGcmSchemeFactoryTest {

    private static byte[] randomKey(int length) {
        byte[] dek = new byte[length];
        new SecureRandom().nextBytes(dek);
        return dek;
    }

    private static TokenizationScheme scheme() {
        CryptoProvider provider = CryptoProviderRegistry.resolve("BCFIPS");
        return TokenizationSchemeRegistry.resolve("AES-GCM", provider);
    }

    @Test
    void registeredUnderKnownIds() {
        assertEquals(true, TokenizationSchemeRegistry.knownIds().contains("AES-GCM"));
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
    void sameInputProducesDifferentTokensEachCall() {
        TokenizationScheme scheme = scheme();
        byte[] dek = randomKey(32);

        String first = scheme.tokenize("repeat-this-value", dek);
        String second = scheme.tokenize("repeat-this-value", dek);
        assertNotEquals(first, second);
        assertEquals("repeat-this-value", scheme.detokenize(first, dek));
        assertEquals("repeat-this-value", scheme.detokenize(second, dek));
    }

    @Test
    void nullValuePassesThroughUnchanged() {
        TokenizationScheme scheme = scheme();
        byte[] dek = randomKey(16);
        assertNull(scheme.tokenize(null, dek));
        assertNull(scheme.detokenize(null, dek));
    }

    @Test
    void tamperedTokenFailsToDetokenize() {
        TokenizationScheme scheme = scheme();
        byte[] dek = randomKey(16);
        // Tamper with the first character rather than the last: the last base64 symbol's
        // low-order bits can be unused padding that Java's decoder ignores, so flipping it
        // doesn't reliably change the decoded bytes. The first character always maps to real
        // high-order bits of the first byte.
        String token = scheme.tokenize("sensitive-value", dek);
        char firstChar = token.charAt(0);
        String tampered = (firstChar == 'A' ? 'B' : 'A') + token.substring(1);

        assertThrows(RuntimeException.class, () -> scheme.detokenize(tampered, dek));
    }

    @Test
    void wrongKeyLengthThrows() {
        TokenizationScheme scheme = scheme();
        assertThrows(RuntimeException.class, () -> scheme.tokenize("value", new byte[8]));
    }
}
