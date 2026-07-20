/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingScheme;
import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingSchemeFactory;

/**
 * Built-in {@code "LAST-NAME-LOOKUP"} algorithm: replaces a value with one of ~100 common
 * surnames bundled in {@code last-names.txt}, selected deterministically by a keyed hash of the
 * input. See {@link NameLookupScheme} for the mechanics.
 */
public final class LastNameLookupSchemeFactory implements OneWayMaskingSchemeFactory {

    @Override
    public String id() {
        return "LAST-NAME-LOOKUP";
    }

    @Override
    public OneWayMaskingScheme create() {
        return new NameLookupScheme("last-names.txt", "LAST-NAME-LOOKUP");
    }
}
