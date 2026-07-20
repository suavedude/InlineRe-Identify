/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;

import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingScheme;

import org.junit.jupiter.api.Test;

class CreditCardMaskSchemeFactoryTest {

    private static byte[] randomKey() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        return key;
    }

    @Test
    void preservesDashSeparatorsAndLength() {
        OneWayMaskingScheme scheme = new CreditCardMaskSchemeFactory().create();
        byte[] key = randomKey();

        String masked = scheme.mask("4111-1111-1111-1111", key);
        assertEquals(19, masked.length());
        assertEquals('-', masked.charAt(4));
        assertEquals('-', masked.charAt(9));
        assertEquals('-', masked.charAt(14));
        assertNotEquals("4111-1111-1111-1111", masked);
        for (char c : masked.replace("-", "").toCharArray()) {
            assertTrue(Character.isDigit(c));
        }
    }

    @Test
    void plainDigitsWithNoSeparatorsWork() {
        OneWayMaskingScheme scheme = new CreditCardMaskSchemeFactory().create();
        byte[] key = randomKey();

        String masked = scheme.mask("4111111111111111", key);
        assertEquals(16, masked.length());
        assertNotEquals("4111111111111111", masked);
    }

    @Test
    void sameInputProducesSameOutput() {
        OneWayMaskingScheme scheme = new CreditCardMaskSchemeFactory().create();
        byte[] key = randomKey();
        assertEquals(scheme.mask("4111-1111-1111-1111", key), scheme.mask("4111-1111-1111-1111", key));
    }

    @Test
    void unsupportedCharacterThrows() {
        OneWayMaskingScheme scheme = new CreditCardMaskSchemeFactory().create();
        assertThrows(RuntimeException.class, () -> scheme.mask("4111/1111/1111/1111", randomKey()));
    }

    @Test
    void noDigitsThrows() {
        OneWayMaskingScheme scheme = new CreditCardMaskSchemeFactory().create();
        assertThrows(RuntimeException.class, () -> scheme.mask("----", randomKey()));
    }

    @Test
    void nullValuePassesThroughUnchanged() {
        OneWayMaskingScheme scheme = new CreditCardMaskSchemeFactory().create();
        assertNull(scheme.mask(null, randomKey()));
    }
}
