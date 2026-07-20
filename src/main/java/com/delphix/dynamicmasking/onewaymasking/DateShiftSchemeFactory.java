/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingScheme;
import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingSchemeFactory;

/**
 * Built-in {@code "DATE-SHIFT"} algorithm: shifts an ISO-8601 date ({@code yyyy-MM-dd}) or
 * date-time ({@code yyyy-MM-dd'T'HH:mm:ss}) by a deterministic pseudorandom number of days in
 * {@code [-365, +365]}, derived from a keyed hash of the input value. The same date + key always
 * shifts by the same amount (referential integrity: date order and gaps between nearby dates are
 * roughly preserved), but the shift amount can't be recovered from the output alone, so the
 * original date isn't reversible from the masked one.
 */
public final class DateShiftSchemeFactory implements OneWayMaskingSchemeFactory {

    static final int MAX_SHIFT_DAYS = 365;

    @Override
    public String id() {
        return "DATE-SHIFT";
    }

    @Override
    public OneWayMaskingScheme create() {
        return new DateShiftScheme();
    }

    private static final class DateShiftScheme implements OneWayMaskingScheme {

        @Override
        public String mask(String value, byte[] key) {
            if (value == null) {
                return null;
            }
            if (value.isEmpty()) {
                return value;
            }
            KeyedLookup.requireNonEmptyKey(key);

            int bound = 2 * MAX_SHIFT_DAYS + 1;
            int offsetDays = KeyedLookup.index(key, "DATE-SHIFT", value, bound) - MAX_SHIFT_DAYS;

            try {
                LocalDateTime dateTime = LocalDateTime.parse(value, DateTimeFormatter.ISO_LOCAL_DATE_TIME);
                return dateTime.plusDays(offsetDays).format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
            } catch (DateTimeParseException dateTimeFailed) {
                try {
                    LocalDate date = LocalDate.parse(value, DateTimeFormatter.ISO_LOCAL_DATE);
                    return date.plusDays(offsetDays).format(DateTimeFormatter.ISO_LOCAL_DATE);
                } catch (DateTimeParseException dateFailed) {
                    throw new OneWayMaskingException(
                            "Value is not an ISO-8601 date (yyyy-MM-dd) or date-time (yyyy-MM-dd'T'HH:mm:ss)");
                }
            }
        }
    }
}
