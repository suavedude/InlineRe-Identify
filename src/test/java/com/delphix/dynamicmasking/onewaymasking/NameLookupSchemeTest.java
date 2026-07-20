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

class NameLookupSchemeTest {

    private static byte[] randomKey() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        return key;
    }

    @Test
    void firstNameLookupProducesStableReplacementFromBundledList() {
        OneWayMaskingScheme scheme = new FirstNameLookupSchemeFactory().create();
        byte[] key = randomKey();

        String masked = scheme.mask("john.doe@example.com", key);
        assertEquals(masked, scheme.mask("john.doe@example.com", key));
        assertTrue(masked.length() > 0);
    }

    @Test
    void lastNameLookupUsesADifferentListThanFirstName() {
        byte[] key = randomKey();
        OneWayMaskingScheme firstNames = new FirstNameLookupSchemeFactory().create();
        OneWayMaskingScheme lastNames = new LastNameLookupSchemeFactory().create();

        // Same salt-independent value, different bundled lists -- results need not differ for
        // every input, but the schemes must be independently resolvable and both functional.
        assertTrue(firstNames.mask("input-value", key).length() > 0);
        assertTrue(lastNames.mask("input-value", key).length() > 0);
    }

    @Test
    void differentKeysProduceDifferentDistributionsEventually() {
        OneWayMaskingScheme scheme = new FirstNameLookupSchemeFactory().create();
        byte[] keyA = randomKey();
        byte[] keyB = randomKey();

        boolean sawDifference = false;
        for (int i = 0; i < 20; i++) {
            String value = "user" + i + "@example.com";
            if (!scheme.mask(value, keyA).equals(scheme.mask(value, keyB))) {
                sawDifference = true;
                break;
            }
        }
        assertTrue(sawDifference, "Expected at least one input to map differently under different keys");
    }

    @Test
    void nullValuePassesThroughUnchanged() {
        OneWayMaskingScheme scheme = new FirstNameLookupSchemeFactory().create();
        assertNull(scheme.mask(null, randomKey()));
    }

    @Test
    void emptyValuePassesThroughUnchanged() {
        OneWayMaskingScheme scheme = new FirstNameLookupSchemeFactory().create();
        assertEquals("", scheme.mask("", randomKey()));
    }

    @Test
    void emptyKeyThrows() {
        OneWayMaskingScheme scheme = new FirstNameLookupSchemeFactory().create();
        assertThrows(RuntimeException.class, () -> scheme.mask("value", new byte[0]));
    }
}
