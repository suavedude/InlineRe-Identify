/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

/** Delphix masking algorithm fixed to the {@code DATE-SHIFT} scheme. See {@link FixedSchemeMaskingAlgorithm}. */
public final class DateShiftMaskingAlgorithm extends FixedSchemeMaskingAlgorithm {

    @Override
    String schemeId() {
        return "DATE-SHIFT";
    }

    @Override
    public String getName() {
        return "Date Shift Masking";
    }

    @Override
    public String getDescription() {
        return "Shifts an ISO-8601 date/date-time by a deterministic pseudorandom number of days in [-365, +365].";
    }
}
