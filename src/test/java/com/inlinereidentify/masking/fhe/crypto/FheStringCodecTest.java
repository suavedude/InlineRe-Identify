/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.inlinereidentify.masking.fhe.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;

import org.junit.jupiter.api.Test;

class FheStringCodecTest {
    private final SecureRandom random = new SecureRandom();

    @Test
    void encryptDecryptRoundTripsPlainAscii() {
        FheSecretKey key = DghvCipher.keyGen("string-roundtrip", FheSecurityProfile.COMPACT);
        String plaintext = "John Smith, SSN 123-45-6789";
        String token = FheStringCodec.encrypt(plaintext, key, random);
        assertEquals(plaintext, FheStringCodec.decrypt(token, key));
    }

    @Test
    void encryptDecryptRoundTripsUnicode() {
        FheSecretKey key = DghvCipher.keyGen("unicode-roundtrip", FheSecurityProfile.COMPACT);
        String plaintext = "héllo wörld éè中文";
        String token = FheStringCodec.encrypt(plaintext, key, random);
        assertEquals(plaintext, FheStringCodec.decrypt(token, key));
    }

    @Test
    void encryptDecryptRoundTripsEmptyString() {
        FheSecretKey key = DghvCipher.keyGen("empty-roundtrip", FheSecurityProfile.COMPACT);
        String token = FheStringCodec.encrypt("", key, random);
        assertEquals("", FheStringCodec.decrypt(token, key));
    }

    @Test
    void sameInputEncryptsDifferentlyEachTime() {
        FheSecretKey key = DghvCipher.keyGen("nondeterministic", FheSecurityProfile.COMPACT);
        String token1 = FheStringCodec.encrypt("repeat-me", key, random);
        String token2 = FheStringCodec.encrypt("repeat-me", key, random);
        assertNotEquals(token1, token2);
        assertEquals("repeat-me", FheStringCodec.decrypt(token1, key));
        assertEquals("repeat-me", FheStringCodec.decrypt(token2, key));
    }

    @Test
    void decryptingWithWrongPassphraseFailsLoudlyOrProducesGarbage() {
        FheSecretKey encryptKey = DghvCipher.keyGen("right-passphrase", FheSecurityProfile.COMPACT);
        FheSecretKey wrongKey = DghvCipher.keyGen("wrong-passphrase", FheSecurityProfile.COMPACT);
        String token = FheStringCodec.encrypt("sensitive value", encryptKey, random);
        assertNotEquals("sensitive value", FheStringCodec.decrypt(token, wrongKey));
    }

    @Test
    void decryptingWithMismatchedProfileThrows() {
        FheSecretKey compactKey = DghvCipher.keyGen("profile-mismatch", FheSecurityProfile.COMPACT);
        FheSecretKey hardenedKey = DghvCipher.keyGen("profile-mismatch", FheSecurityProfile.HARDENED);
        String token = FheStringCodec.encrypt("value", compactKey, random);
        assertThrows(IllegalArgumentException.class, () -> FheStringCodec.decrypt(token, hardenedKey));
    }
}
