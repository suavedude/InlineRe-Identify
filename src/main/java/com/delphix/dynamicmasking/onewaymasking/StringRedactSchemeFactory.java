/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingScheme;
import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingSchemeFactory;

/**
 * Built-in {@code "STRING-REDACT"} algorithm: overwrites every character of the value with
 * {@code 'X'}, preserving only the original length. Static -- the key is accepted for interface
 * uniformity but ignored, since there's nothing to keep consistent across calls beyond length.
 */
public final class StringRedactSchemeFactory implements OneWayMaskingSchemeFactory {

    private static final char REDACTION_CHAR = 'X';

    @Override
    public String id() {
        return "STRING-REDACT";
    }

    @Override
    public OneWayMaskingScheme create() {
        return (value, key) -> {
            if (value == null) {
                return null;
            }
            char[] redacted = new char[value.length()];
            java.util.Arrays.fill(redacted, REDACTION_CHAR);
            return new String(redacted);
        };
    }
}
