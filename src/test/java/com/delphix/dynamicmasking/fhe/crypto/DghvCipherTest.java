/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.fhe.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.junit.jupiter.api.Test;

class DghvCipherTest {
    private final SecureRandom random = new SecureRandom();

    @Test
    void keyGenIsDeterministicForSamePassphrase() {
        FheSecretKey key1 = DghvCipher.keyGen("correct horse battery staple", FheSecurityProfile.COMPACT);
        FheSecretKey key2 = DghvCipher.keyGen("correct horse battery staple", FheSecurityProfile.COMPACT);
        assertEquals(key1.getP(), key2.getP());
    }

    @Test
    void keyGenDiffersForDifferentPassphrases() {
        FheSecretKey key1 = DghvCipher.keyGen("passphrase-one", FheSecurityProfile.COMPACT);
        FheSecretKey key2 = DghvCipher.keyGen("passphrase-two", FheSecurityProfile.COMPACT);
        assertNotEquals(key1.getP(), key2.getP());
    }

    @Test
    void encryptDecryptRoundTripsForBothBitValues() {
        FheSecretKey key = DghvCipher.keyGen("bit-roundtrip", FheSecurityProfile.COMPACT);
        for (int bit = 0; bit <= 1; bit++) {
            for (int trial = 0; trial < 20; trial++) {
                BigInteger ciphertext = DghvCipher.encryptBit(bit, key, random);
                assertEquals(bit, DghvCipher.decryptBit(ciphertext, key));
            }
        }
    }

    @Test
    void encryptionIsProbabilistic() {
        FheSecretKey key = DghvCipher.keyGen("probabilistic", FheSecurityProfile.COMPACT);
        BigInteger c1 = DghvCipher.encryptBit(1, key, random);
        BigInteger c2 = DghvCipher.encryptBit(1, key, random);
        assertNotEquals(c1, c2);
    }

    @Test
    void homomorphicAddComputesXorOfPlaintextBits() {
        FheSecretKey key = DghvCipher.keyGen("xor-test", FheSecurityProfile.COMPACT);
        for (int a = 0; a <= 1; a++) {
            for (int b = 0; b <= 1; b++) {
                BigInteger ca = DghvCipher.encryptBit(a, key, random);
                BigInteger cb = DghvCipher.encryptBit(b, key, random);
                BigInteger sum = DghvCipher.homomorphicAdd(ca, cb);
                assertEquals(a ^ b, DghvCipher.decryptBit(sum, key));
            }
        }
    }

    @Test
    void homomorphicMultiplyComputesAndOfPlaintextBits() {
        FheSecretKey key = DghvCipher.keyGen("and-test", FheSecurityProfile.COMPACT);
        for (int a = 0; a <= 1; a++) {
            for (int b = 0; b <= 1; b++) {
                BigInteger ca = DghvCipher.encryptBit(a, key, random);
                BigInteger cb = DghvCipher.encryptBit(b, key, random);
                BigInteger product = DghvCipher.homomorphicMultiply(ca, cb);
                assertEquals(a & b, DghvCipher.decryptBit(product, key));
            }
        }
    }
}
