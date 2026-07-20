/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

/** Delphix masking algorithm fixed to the {@code FIRST-NAME-LOOKUP} scheme. See {@link FixedSchemeMaskingAlgorithm}. */
public final class FirstNameMaskingAlgorithm extends FixedSchemeMaskingAlgorithm {

    @Override
    String schemeId() {
        return "FIRST-NAME-LOOKUP";
    }

    @Override
    public String getName() {
        return "First Name Masking";
    }

    @Override
    public String getDescription() {
        return "Replaces the whole value with one of ~100 common first names, selected deterministically by a keyed hash.";
    }
}
