/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingScheme;
import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingSchemeFactory;

/**
 * Built-in {@code "NUMBER-REDACT"} algorithm: replaces any value with the fixed string
 * {@code "42"}. Static -- the key is accepted for interface uniformity but ignored.
 */
public final class NumberRedactSchemeFactory implements OneWayMaskingSchemeFactory {

    private static final String REDACTION_VALUE = "42";

    @Override
    public String id() {
        return "NUMBER-REDACT";
    }

    @Override
    public OneWayMaskingScheme create() {
        return (value, key) -> value == null ? null : REDACTION_VALUE;
    }
}
