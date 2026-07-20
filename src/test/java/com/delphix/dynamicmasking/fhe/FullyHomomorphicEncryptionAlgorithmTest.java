/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.fhe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.delphix.masking.api.plugin.MaskingAlgorithm.MaskingMode;
import com.delphix.masking.api.plugin.exception.ComponentConfigurationException;
import com.delphix.masking.api.plugin.exception.MaskingException;
import com.delphix.dynamicmasking.fhe.crypto.FheSecurityProfile;

import org.junit.jupiter.api.Test;

class FullyHomomorphicEncryptionAlgorithmTest {

    @Test
    void maskThenReidentifyRecoversOriginalValue() throws MaskingException {
        FullyHomomorphicEncryptionAlgorithm masker = new FullyHomomorphicEncryptionAlgorithm();
        masker.setSecretPassphrase("plugin-roundtrip-secret");
        masker.setMaskingMode(MaskingMode.MASK);

        String original = "4111-1111-1111-1111";
        String masked = masker.mask(original);
        assertNotEquals(original, masked);

        FullyHomomorphicEncryptionAlgorithm reidentifier = new FullyHomomorphicEncryptionAlgorithm();
        reidentifier.setSecretPassphrase("plugin-roundtrip-secret");
        reidentifier.setMaskingMode(MaskingMode.REIDENTIFY);

        assertEquals(original, reidentifier.mask(masked));
    }

    @Test
    void nullValuePassesThroughUnchanged() throws MaskingException {
        FullyHomomorphicEncryptionAlgorithm masker = new FullyHomomorphicEncryptionAlgorithm();
        masker.setSecretPassphrase("irrelevant");
        assertNull(masker.mask(null));
    }

    @Test
    void validateRejectsMissingPassphrase() {
        FullyHomomorphicEncryptionAlgorithm masker = new FullyHomomorphicEncryptionAlgorithm();
        assertThrows(ComponentConfigurationException.class, masker::validate);
    }

    @Test
    void validateRejectsUnknownSecurityProfile() {
        FullyHomomorphicEncryptionAlgorithm masker = new FullyHomomorphicEncryptionAlgorithm();
        masker.setSecretPassphrase("some-secret");
        masker.setSecurityProfile("NOT_A_REAL_PROFILE");
        assertThrows(ComponentConfigurationException.class, masker::validate);
    }

    @Test
    void validatePassesWithGoodConfiguration() throws ComponentConfigurationException {
        FullyHomomorphicEncryptionAlgorithm masker = new FullyHomomorphicEncryptionAlgorithm();
        masker.setSecretPassphrase("some-secret");
        masker.setSecurityProfile(FheSecurityProfile.HARDENED.name());
        masker.validate();
    }
}
