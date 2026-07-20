/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingScheme;

import org.junit.jupiter.api.Test;

class RedactSchemeFactoriesTest {

    @Test
    void stringRedactOverwritesEachCharacterPreservingLength() {
        OneWayMaskingScheme scheme = new StringRedactSchemeFactory().create();
        assertEquals("XXXXX", scheme.mask("hello", null));
        assertNull(scheme.mask(null, null));
    }

    @Test
    void numberRedactReplacesWithFixedValue() {
        OneWayMaskingScheme scheme = new NumberRedactSchemeFactory().create();
        assertEquals("42", scheme.mask("123456789", null));
        assertNull(scheme.mask(null, null));
    }

    @Test
    void dateRedactReplacesWithFixedValue() {
        OneWayMaskingScheme scheme = new DateRedactSchemeFactory().create();
        assertEquals("1990-02-12T10:00:00", scheme.mask("2024-06-01T00:00:00", null));
        assertNull(scheme.mask(null, null));
    }
}
