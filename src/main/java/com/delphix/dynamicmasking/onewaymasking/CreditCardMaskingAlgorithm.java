/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

/** Delphix masking algorithm fixed to the {@code CREDIT-CARD-MASK} scheme. See {@link FixedSchemeMaskingAlgorithm}. */
public final class CreditCardMaskingAlgorithm extends FixedSchemeMaskingAlgorithm {

    @Override
    String schemeId() {
        return "CREDIT-CARD-MASK";
    }

    @Override
    public String getName() {
        return "Credit Card Masking";
    }

    @Override
    public String getDescription() {
        return "Substitutes a card number's digits in format-preserving 4-digit segments, keeping any - or space separators.";
    }
}
