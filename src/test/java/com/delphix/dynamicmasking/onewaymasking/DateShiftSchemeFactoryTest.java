/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;

import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingScheme;

import org.junit.jupiter.api.Test;

class DateShiftSchemeFactoryTest {

    private static byte[] randomKey() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        return key;
    }

    @Test
    void shiftsDateOnlyValueWithinBound() {
        OneWayMaskingScheme scheme = new DateShiftSchemeFactory().create();
        byte[] key = randomKey();

        String masked = scheme.mask("1990-02-12", key);
        LocalDate original = LocalDate.parse("1990-02-12");
        LocalDate shifted = LocalDate.parse(masked);
        long deltaDays = Math.abs(ChronoUnit.DAYS.between(original, shifted));
        assertTrue(deltaDays <= DateShiftSchemeFactory.MAX_SHIFT_DAYS);
    }

    @Test
    void shiftsDateTimeValue() {
        OneWayMaskingScheme scheme = new DateShiftSchemeFactory().create();
        byte[] key = randomKey();

        String masked = scheme.mask("1990-02-12T10:00:00", key);
        assertTrue(masked.contains("T"));
    }

    @Test
    void sameInputAndKeyProduceSameShift() {
        OneWayMaskingScheme scheme = new DateShiftSchemeFactory().create();
        byte[] key = randomKey();
        assertEquals(scheme.mask("2000-01-01", key), scheme.mask("2000-01-01", key));
    }

    @Test
    void nonDateValueThrows() {
        OneWayMaskingScheme scheme = new DateShiftSchemeFactory().create();
        assertThrows(RuntimeException.class, () -> scheme.mask("not-a-date", randomKey()));
    }

    @Test
    void nullValuePassesThroughUnchanged() {
        OneWayMaskingScheme scheme = new DateShiftSchemeFactory().create();
        assertNull(scheme.mask(null, randomKey()));
    }
}
