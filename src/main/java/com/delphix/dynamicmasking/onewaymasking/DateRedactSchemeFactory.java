/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingScheme;
import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingSchemeFactory;

/**
 * Built-in {@code "DATE-REDACT"} algorithm: replaces any value with the fixed date-time string
 * {@code "1990-02-12T10:00:00"}. Static -- the key is accepted for interface uniformity but
 * ignored.
 */
public final class DateRedactSchemeFactory implements OneWayMaskingSchemeFactory {

    private static final String REDACTION_VALUE = "1990-02-12T10:00:00";

    @Override
    public String id() {
        return "DATE-REDACT";
    }

    @Override
    public OneWayMaskingScheme create() {
        return (value, key) -> value == null ? null : REDACTION_VALUE;
    }
}
