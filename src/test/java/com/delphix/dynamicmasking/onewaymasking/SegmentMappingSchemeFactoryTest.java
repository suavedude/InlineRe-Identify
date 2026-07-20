/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;

import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingScheme;

import org.junit.jupiter.api.Test;

class SegmentMappingSchemeFactoryTest {

    private static byte[] randomKey() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        return key;
    }

    @Test
    void masksFullSegmentsPreservingLength() {
        OneWayMaskingScheme scheme = new SegmentMappingSchemeFactory().create();
        byte[] key = randomKey();

        String masked = scheme.mask("4111111111111111", key);
        assertEquals(16, masked.length());
        assertNotEquals("4111111111111111", masked);
        for (char c : masked.toCharArray()) {
            org.junit.jupiter.api.Assertions.assertTrue(Character.isDigit(c));
        }
    }

    @Test
    void masksPartialTrailingSegmentPreservingLength() {
        OneWayMaskingScheme scheme = new SegmentMappingSchemeFactory().create();
        byte[] key = randomKey();

        String masked = scheme.mask("123456", key); // one full segment + 2-digit remainder
        assertEquals(6, masked.length());
    }

    @Test
    void sameInputProducesSameOutput() {
        OneWayMaskingScheme scheme = new SegmentMappingSchemeFactory().create();
        byte[] key = randomKey();
        assertEquals(scheme.mask("999988887777", key), scheme.mask("999988887777", key));
    }

    @Test
    void nonDigitCharacterThrows() {
        OneWayMaskingScheme scheme = new SegmentMappingSchemeFactory().create();
        assertThrows(RuntimeException.class, () -> scheme.mask("4111-1111", randomKey()));
    }

    @Test
    void nullValuePassesThroughUnchanged() {
        OneWayMaskingScheme scheme = new SegmentMappingSchemeFactory().create();
        assertNull(scheme.mask(null, randomKey()));
    }
}
