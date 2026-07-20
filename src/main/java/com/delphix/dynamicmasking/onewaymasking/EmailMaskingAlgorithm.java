/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

/** Delphix masking algorithm fixed to the {@code EMAIL-MASK} scheme. See {@link FixedSchemeMaskingAlgorithm}. */
public final class EmailMaskingAlgorithm extends FixedSchemeMaskingAlgorithm {

    @Override
    String schemeId() {
        return "EMAIL-MASK";
    }

    @Override
    public String getName() {
        return "Email Masking";
    }

    @Override
    public String getDescription() {
        return "Redacts the local part of an email address, keeping the domain readable.";
    }
}
