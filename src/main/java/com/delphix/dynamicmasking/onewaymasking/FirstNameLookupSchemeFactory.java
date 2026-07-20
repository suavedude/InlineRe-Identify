/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingScheme;
import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingSchemeFactory;

/**
 * Built-in {@code "FIRST-NAME-LOOKUP"} algorithm: replaces a value with one of ~100 common first
 * names bundled in {@code first-names.txt}, selected deterministically by a keyed hash of the
 * input. See {@link NameLookupScheme} for the mechanics.
 */
public final class FirstNameLookupSchemeFactory implements OneWayMaskingSchemeFactory {

    @Override
    public String id() {
        return "FIRST-NAME-LOOKUP";
    }

    @Override
    public OneWayMaskingScheme create() {
        return new NameLookupScheme("first-names.txt", "FIRST-NAME-LOOKUP");
    }
}
