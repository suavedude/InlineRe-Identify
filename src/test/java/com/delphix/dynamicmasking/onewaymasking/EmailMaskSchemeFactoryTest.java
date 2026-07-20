/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingScheme;

import org.junit.jupiter.api.Test;

class EmailMaskSchemeFactoryTest {

    @Test
    void keepsFirstCharacterAndDomainRedactsRest() {
        OneWayMaskingScheme scheme = new EmailMaskSchemeFactory().create();
        assertEquals("jXXXXXXX@example.com", scheme.mask("jane.doe@example.com", null));
    }

    @Test
    void singleCharacterLocalPart() {
        OneWayMaskingScheme scheme = new EmailMaskSchemeFactory().create();
        assertEquals("a@example.com", scheme.mask("a@example.com", null));
    }

    @Test
    void missingAtSignThrows() {
        OneWayMaskingScheme scheme = new EmailMaskSchemeFactory().create();
        assertThrows(RuntimeException.class, () -> scheme.mask("not-an-email", null));
    }

    @Test
    void emptyLocalPartThrows() {
        OneWayMaskingScheme scheme = new EmailMaskSchemeFactory().create();
        assertThrows(RuntimeException.class, () -> scheme.mask("@example.com", null));
    }

    @Test
    void emptyDomainThrows() {
        OneWayMaskingScheme scheme = new EmailMaskSchemeFactory().create();
        assertThrows(RuntimeException.class, () -> scheme.mask("jane.doe@", null));
    }

    @Test
    void nullValuePassesThroughUnchanged() {
        OneWayMaskingScheme scheme = new EmailMaskSchemeFactory().create();
        assertNull(scheme.mask(null, null));
    }
}
