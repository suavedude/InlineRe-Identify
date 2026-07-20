/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

/** Delphix masking algorithm fixed to the {@code SEGMENT-MAPPING} scheme. See {@link FixedSchemeMaskingAlgorithm}. */
public final class SegmentMappingMaskingAlgorithm extends FixedSchemeMaskingAlgorithm {

    @Override
    String schemeId() {
        return "SEGMENT-MAPPING";
    }

    @Override
    public String getName() {
        return "Segment Mapping Masking";
    }

    @Override
    public String getDescription() {
        return "Substitutes a digits-only value in fixed 4-digit segments via a keyed, shuffled lookup table per segment."
                + " Rejects separators -- see Credit Card Masking for a format-preserving variant.";
    }
}
