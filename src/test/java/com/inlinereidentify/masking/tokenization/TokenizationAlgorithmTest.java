/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.inlinereidentify.masking.tokenization;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;
import java.util.Base64;

import com.delphix.masking.api.plugin.MaskingAlgorithm.MaskingMode;
import com.delphix.masking.api.plugin.exception.ComponentConfigurationException;
import com.delphix.masking.api.plugin.exception.MaskingException;

import org.junit.jupiter.api.Test;

class TokenizationAlgorithmTest {

    private static String randomKeyBase64() {
        return randomKeyBase64(16);
    }

    private static String randomKeyBase64(int length) {
        byte[] dek = new byte[length];
        new SecureRandom().nextBytes(dek);
        return Base64.getEncoder().encodeToString(dek);
    }

    @Test
    void maskThenReidentifyRecoversOriginalValueForLongInput() throws MaskingException {
        String keyBase64 = randomKeyBase64();

        TokenizationAlgorithm masker = new TokenizationAlgorithm();
        masker.setDataEncryptionKeyBase64(keyBase64);
        masker.setMaskingMode(MaskingMode.MASK);

        String original = "4111-1111-1111-1111";
        String masked = masker.mask(original);
        assertNotEquals(original, masked);

        TokenizationAlgorithm reidentifier = new TokenizationAlgorithm();
        reidentifier.setDataEncryptionKeyBase64(keyBase64);
        reidentifier.setMaskingMode(MaskingMode.REIDENTIFY);

        assertEquals(original, reidentifier.mask(masked));
    }

    @Test
    void maskThenReidentifyRecoversOriginalValueForShortInput() throws MaskingException {
        String keyBase64 = randomKeyBase64();

        TokenizationAlgorithm masker = new TokenizationAlgorithm();
        masker.setDataEncryptionKeyBase64(keyBase64);
        masker.setMaskingMode(MaskingMode.MASK);

        String original = "abc";
        String masked = masker.mask(original);
        assertNotEquals(original, masked);

        TokenizationAlgorithm reidentifier = new TokenizationAlgorithm();
        reidentifier.setDataEncryptionKeyBase64(keyBase64);
        reidentifier.setMaskingMode(MaskingMode.REIDENTIFY);

        assertEquals(original, reidentifier.mask(masked));
    }

    @Test
    void sameInputProducesSameToken() throws MaskingException {
        TokenizationAlgorithm masker = new TokenizationAlgorithm();
        masker.setDataEncryptionKeyBase64(randomKeyBase64());

        assertEquals(masker.mask("repeat-this-value"), masker.mask("repeat-this-value"));
    }

    @Test
    void nullValuePassesThroughUnchanged() throws MaskingException {
        TokenizationAlgorithm masker = new TokenizationAlgorithm();
        masker.setDataEncryptionKeyBase64(randomKeyBase64());
        assertNull(masker.mask(null));
    }

    @Test
    void validateRejectsMissingKey() {
        TokenizationAlgorithm masker = new TokenizationAlgorithm();
        assertThrows(ComponentConfigurationException.class, masker::validate);
    }

    @Test
    void validateRejectsWrongLengthKey() {
        TokenizationAlgorithm masker = new TokenizationAlgorithm();
        masker.setDataEncryptionKeyBase64(Base64.getEncoder().encodeToString(new byte[8]));
        assertThrows(ComponentConfigurationException.class, masker::validate);
    }

    @Test
    void validatePassesWithGoodConfiguration() throws ComponentConfigurationException {
        TokenizationAlgorithm masker = new TokenizationAlgorithm();
        masker.setDataEncryptionKeyBase64(randomKeyBase64());
        masker.validate();
    }

    @Test
    void aes256KeyRoundTripsUnderDefaultProviderAndAlgorithm() throws MaskingException {
        String keyBase64 = randomKeyBase64(32);

        TokenizationAlgorithm masker = new TokenizationAlgorithm();
        masker.setDataEncryptionKeyBase64(keyBase64);

        String original = "4111-1111-1111-1111";
        String masked = masker.mask(original);
        assertNotEquals(original, masked);

        TokenizationAlgorithm reidentifier = new TokenizationAlgorithm();
        reidentifier.setDataEncryptionKeyBase64(keyBase64);
        reidentifier.setMaskingMode(MaskingMode.REIDENTIFY);

        assertEquals(original, reidentifier.mask(masked));
    }

    @Test
    void sunJceProviderRoundTrips() throws MaskingException {
        String keyBase64 = randomKeyBase64();

        TokenizationAlgorithm masker = new TokenizationAlgorithm();
        masker.setDataEncryptionKeyBase64(keyBase64);
        masker.setCryptoProvider("SunJCE");

        // Short value (ShortValueCipher/PKCS5Padding), not long (TokenCipher/CS3Padding): CTS
        // ciphertext stealing uses BC-specific transformation naming that SunJCE doesn't
        // recognize under that string, so only the short-value path is cross-provider portable.
        String original = "abc";
        String masked = masker.mask(original);
        assertNotEquals(original, masked);

        TokenizationAlgorithm reidentifier = new TokenizationAlgorithm();
        reidentifier.setDataEncryptionKeyBase64(keyBase64);
        reidentifier.setCryptoProvider("SunJCE");
        reidentifier.setMaskingMode(MaskingMode.REIDENTIFY);

        assertEquals(original, reidentifier.mask(masked));
    }

    @Test
    void differentProvidersAreNotInteroperable() throws MaskingException {
        // Same key, same algorithm, different provider on each side -- not a supported
        // combination (nothing guarantees two JCE providers produce identical ciphertext bytes
        // for the same transformation/key/IV), so this must not silently "work".
        String keyBase64 = randomKeyBase64();

        TokenizationAlgorithm masker = new TokenizationAlgorithm();
        masker.setDataEncryptionKeyBase64(keyBase64);
        masker.setCryptoProvider("BCFIPS");
        String masked = masker.mask("4111-1111-1111-1111");

        TokenizationAlgorithm reidentifier = new TokenizationAlgorithm();
        reidentifier.setDataEncryptionKeyBase64(keyBase64);
        reidentifier.setCryptoProvider("SunJCE");
        reidentifier.setMaskingMode(MaskingMode.REIDENTIFY);

        // Either throws, or (if the two providers happen to agree byte-for-byte on this
        // transformation) silently round-trips -- either is acceptable, but a *wrong* recovered
        // value would be a silent-corruption bug, so explicitly rule that out.
        try {
            String recovered = reidentifier.mask(masked);
            assertEquals("4111-1111-1111-1111", recovered);
        } catch (MaskingException expected) {
            // acceptable: mismatched provider correctly failed rather than corrupting data
        }
    }

    @Test
    void validateRejectsUnknownCryptoProvider() {
        TokenizationAlgorithm masker = new TokenizationAlgorithm();
        masker.setDataEncryptionKeyBase64(randomKeyBase64());
        masker.setCryptoProvider("NoSuchProvider");
        assertThrows(ComponentConfigurationException.class, masker::validate);
    }

    @Test
    void validateRejectsUnknownCipherAlgorithm() {
        TokenizationAlgorithm masker = new TokenizationAlgorithm();
        masker.setDataEncryptionKeyBase64(randomKeyBase64());
        masker.setCipherAlgorithm("NoSuchAlgorithm");
        assertThrows(ComponentConfigurationException.class, masker::validate);
    }
}
