/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking.spi;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;

import org.junit.jupiter.api.Test;

class OneWayMaskingSchemeRegistryTest {

    @Test
    void knownIdsIncludesAllBuiltIns() {
        var ids = OneWayMaskingSchemeRegistry.knownIds();
        assertTrue(ids.contains("FIRST-NAME-LOOKUP"));
        assertTrue(ids.contains("LAST-NAME-LOOKUP"));
        assertTrue(ids.contains("DATE-SHIFT"));
        assertTrue(ids.contains("SEGMENT-MAPPING"));
        assertTrue(ids.contains("STRING-REDACT"));
        assertTrue(ids.contains("NUMBER-REDACT"));
        assertTrue(ids.contains("DATE-REDACT"));
    }

    @Test
    void resolvesCaseInsensitively() {
        assertNotNull(OneWayMaskingSchemeRegistry.resolve("first-name-lookup"));
    }

    @Test
    void unknownSchemeIdThrowsWithKnownIdsListed() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> OneWayMaskingSchemeRegistry.resolve("NoSuchScheme"));
        assertTrue(e.getMessage().contains("NoSuchScheme"));
        assertTrue(e.getMessage().contains("FIRST-NAME-LOOKUP"));
    }

    @Test
    void resolvedSchemeMasksDeterministically() {
        OneWayMaskingScheme scheme = OneWayMaskingSchemeRegistry.resolve("FIRST-NAME-LOOKUP");
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);

        String first = scheme.mask("alice@example.com", key);
        String second = scheme.mask("alice@example.com", key);
        assertEquals(first, second);
    }
}
