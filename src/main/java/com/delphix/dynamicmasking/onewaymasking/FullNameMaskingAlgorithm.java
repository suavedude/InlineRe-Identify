/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

/** Delphix masking algorithm fixed to the {@code FULL-NAME-MASK} scheme. See {@link FixedSchemeMaskingAlgorithm}. */
public final class FullNameMaskingAlgorithm extends FixedSchemeMaskingAlgorithm {

    @Override
    String schemeId() {
        return "FULL-NAME-MASK";
    }

    @Override
    public String getName() {
        return "Full Name Masking";
    }

    @Override
    public String getDescription() {
        return "Replaces a \"First Last\" value with a realistic-looking replacement name, token by token.";
    }
}
