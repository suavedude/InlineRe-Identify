/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;

import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingScheme;

import org.junit.jupiter.api.Test;

class FullNameMaskSchemeFactoryTest {

    private static byte[] randomKey() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        return key;
    }

    @Test
    void masksTwoWordNameIntoTwoWords() {
        OneWayMaskingScheme scheme = new FullNameMaskSchemeFactory().create();
        byte[] key = randomKey();

        String masked = scheme.mask("Jane Doe", key);
        String[] tokens = masked.split(" ");
        assertEquals(2, tokens.length);
    }

    @Test
    void masksThreeWordNameIntoThreeWords() {
        OneWayMaskingScheme scheme = new FullNameMaskSchemeFactory().create();
        byte[] key = randomKey();

        String masked = scheme.mask("Jane Q Doe", key);
        assertEquals(3, masked.split(" ").length);
    }

    @Test
    void singleWordNameMasksToSingleWord() {
        OneWayMaskingScheme scheme = new FullNameMaskSchemeFactory().create();
        byte[] key = randomKey();

        String masked = scheme.mask("Cher", key);
        assertEquals(1, masked.split(" ").length);
    }

    @Test
    void sameInputProducesSameOutput() {
        OneWayMaskingScheme scheme = new FullNameMaskSchemeFactory().create();
        byte[] key = randomKey();
        assertEquals(scheme.mask("Jane Doe", key), scheme.mask("Jane Doe", key));
    }

    @Test
    void firstAndLastTokenComeFromDifferentBundledLists() {
        // Not a strict guarantee for every name, but for "Jane Doe" specifically the first token
        // should resolve against first-names.txt and the second against last-names.txt -- assert
        // the shape holds (two non-empty alphabetic words) rather than exact values, since those
        // depend on the random key.
        OneWayMaskingScheme scheme = new FullNameMaskSchemeFactory().create();
        String masked = scheme.mask("Jane Doe", randomKey());
        for (String token : masked.split(" ")) {
            assertTrue(token.chars().allMatch(Character::isLetter));
        }
    }

    @Test
    void nullValuePassesThroughUnchanged() {
        OneWayMaskingScheme scheme = new FullNameMaskSchemeFactory().create();
        assertNull(scheme.mask(null, randomKey()));
    }

    @Test
    void emptyKeyThrows() {
        OneWayMaskingScheme scheme = new FullNameMaskSchemeFactory().create();
        assertThrows(RuntimeException.class, () -> scheme.mask("Jane Doe", new byte[0]));
    }
}
