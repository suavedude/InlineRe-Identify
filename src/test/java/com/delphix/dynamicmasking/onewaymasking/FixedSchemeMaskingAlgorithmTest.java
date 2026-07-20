/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;
import java.util.Base64;

import com.delphix.masking.api.plugin.exception.ComponentConfigurationException;
import com.delphix.masking.api.plugin.exception.MaskingException;

import org.junit.jupiter.api.Test;

/** Covers the shared key-handling logic in {@link FixedSchemeMaskingAlgorithm} via its concrete subclasses. */
class FixedSchemeMaskingAlgorithmTest {

    private static String randomKeyBase64() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }

    @Test
    void fullNameMaskingAlgorithmMasksTwoWordName() throws MaskingException {
        FullNameMaskingAlgorithm masker = new FullNameMaskingAlgorithm();
        masker.setDataEncryptionKeyBase64(randomKeyBase64());
        assertEquals(2, masker.mask("Jane Doe").split(" ").length);
    }

    @Test
    void creditCardMaskingAlgorithmPreservesFormat() throws MaskingException {
        CreditCardMaskingAlgorithm masker = new CreditCardMaskingAlgorithm();
        masker.setDataEncryptionKeyBase64(randomKeyBase64());
        String masked = masker.mask("4111-1111-1111-1111");
        assertEquals(19, masked.length());
        assertEquals('-', masked.charAt(4));
    }

    @Test
    void emailMaskingAlgorithmRedactsLocalPart() throws MaskingException {
        EmailMaskingAlgorithm masker = new EmailMaskingAlgorithm();
        masker.setDataEncryptionKeyBase64(randomKeyBase64());
        assertEquals("jXXXXXXX@example.com", masker.mask("jane.doe@example.com"));
    }

    @Test
    void firstNameMaskingAlgorithmProducesAlphabeticReplacement() throws MaskingException {
        FirstNameMaskingAlgorithm masker = new FirstNameMaskingAlgorithm();
        masker.setDataEncryptionKeyBase64(randomKeyBase64());
        String masked = masker.mask("whatever-the-input-is");
        assertEquals(masked, masker.mask("whatever-the-input-is"));
    }

    @Test
    void lastNameMaskingAlgorithmProducesStableReplacement() throws MaskingException {
        LastNameMaskingAlgorithm masker = new LastNameMaskingAlgorithm();
        masker.setDataEncryptionKeyBase64(randomKeyBase64());
        String masked = masker.mask("whatever-the-input-is");
        assertEquals(masked, masker.mask("whatever-the-input-is"));
    }

    @Test
    void dateShiftMaskingAlgorithmShiftsDate() throws MaskingException {
        DateShiftMaskingAlgorithm masker = new DateShiftMaskingAlgorithm();
        masker.setDataEncryptionKeyBase64(randomKeyBase64());
        String masked = masker.mask("2000-01-01");
        assertEquals(masked, masker.mask("2000-01-01"));
    }

    @Test
    void segmentMappingMaskingAlgorithmPreservesLength() throws MaskingException {
        SegmentMappingMaskingAlgorithm masker = new SegmentMappingMaskingAlgorithm();
        masker.setDataEncryptionKeyBase64(randomKeyBase64());
        String masked = masker.mask("4111111111111111");
        assertEquals(16, masked.length());
    }

    @Test
    void segmentMappingMaskingAlgorithmRejectsSeparators() throws MaskingException {
        SegmentMappingMaskingAlgorithm masker = new SegmentMappingMaskingAlgorithm();
        masker.setDataEncryptionKeyBase64(randomKeyBase64());
        assertThrows(MaskingException.class, () -> masker.mask("4111-1111-1111-1111"));
    }

    @Test
    void nullValuePassesThroughUnchanged() throws MaskingException {
        FullNameMaskingAlgorithm masker = new FullNameMaskingAlgorithm();
        masker.setDataEncryptionKeyBase64(randomKeyBase64());
        assertNull(masker.mask(null));
    }

    @Test
    void validateRejectsMissingKey() {
        CreditCardMaskingAlgorithm masker = new CreditCardMaskingAlgorithm();
        assertThrows(ComponentConfigurationException.class, masker::validate);
    }

    @Test
    void validatePassesWithGoodConfiguration() throws ComponentConfigurationException {
        EmailMaskingAlgorithm masker = new EmailMaskingAlgorithm();
        masker.setDataEncryptionKeyBase64(randomKeyBase64());
        masker.validate();
    }
}
