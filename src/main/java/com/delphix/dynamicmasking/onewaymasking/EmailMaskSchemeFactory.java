/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

import java.util.Arrays;

import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingScheme;
import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingSchemeFactory;

/**
 * Built-in {@code "EMAIL-MASK"} algorithm: redacts the local part of an email address (all but
 * its first character, replaced with {@code X}) while leaving the domain intact -- {@code
 * "jane.doe@example.com"} becomes {@code "jXXXXXXX@example.com"}. Keeping the domain readable
 * (rather than redacting the whole address) is deliberate: it's rarely sensitive on its own and
 * staying visible lets masked data still be grouped/filtered by domain. Purely structural --
 * ignores the key, like the other static redaction schemes -- so it doesn't preserve
 * referential integrity beyond "same local-part length in, same length out"; two different local
 * parts of the same length redact to visually identical output. Throws if there's no {@code @}
 * (or nothing on either side of it).
 */
public final class EmailMaskSchemeFactory implements OneWayMaskingSchemeFactory {

    @Override
    public String id() {
        return "EMAIL-MASK";
    }

    @Override
    public OneWayMaskingScheme create() {
        return new EmailMaskScheme();
    }

    private static final class EmailMaskScheme implements OneWayMaskingScheme {

        @Override
        public String mask(String value, byte[] key) {
            if (value == null) {
                return null;
            }
            if (value.isEmpty()) {
                return value;
            }

            int at = value.lastIndexOf('@');
            if (at <= 0 || at == value.length() - 1) {
                throw new OneWayMaskingException(
                        "Value is not a valid email address (expected \"local-part@domain\")");
            }

            String localPart = value.substring(0, at);
            String domain = value.substring(at + 1);

            char[] redacted = localPart.toCharArray();
            Arrays.fill(redacted, 1, redacted.length, 'X');
            return new String(redacted) + "@" + domain;
        }
    }
}
