/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

/** Delphix masking algorithm fixed to the {@code LAST-NAME-LOOKUP} scheme. See {@link FixedSchemeMaskingAlgorithm}. */
public final class LastNameMaskingAlgorithm extends FixedSchemeMaskingAlgorithm {

    @Override
    String schemeId() {
        return "LAST-NAME-LOOKUP";
    }

    @Override
    public String getName() {
        return "Last Name Masking";
    }

    @Override
    public String getDescription() {
        return "Replaces the whole value with one of ~100 common surnames, selected deterministically by a keyed hash.";
    }
}
