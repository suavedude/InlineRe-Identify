/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.inlinereidentify.masking.fhe.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * A from-scratch implementation of the symmetric variant of the DGHV "Fully Homomorphic
 * Encryption over the Integers" scheme (van Dijk, Gentry, Halevi, Vaikuntanathan, EUROCRYPT
 * 2010), one of the integer-based FHE constructions surveyed by NIST's Privacy-Enhancing
 * Cryptography project (https://csrc.nist.gov/Projects/pec/fhe).
 *
 * <p>Each plaintext bit {@code m in {0,1}} is encrypted as
 * {@code c = p*q + 2*r + m}, for secret odd integer {@code p}, random large {@code q}, and
 * random small noise {@code r}. Decryption recovers {@code m = (c mod p) mod 2}. Because the
 * noise term is additive/multiplicative under {@code +} and {@code *} on the integers, the
 * scheme is homomorphic for a bounded number of operations before the noise grows large enough
 * to corrupt decryption - see {@link #homomorphicAdd} and {@link #homomorphicMultiply}.
 *
 * <p>This implementation deliberately omits bootstrapping (the step that turns the "somewhat
 * homomorphic" scheme into a scheme supporting unbounded-depth computation), since the masking
 * plugin built on top of it only needs single-shot encrypt/decrypt, not arbitrary homomorphic
 * circuits. It also has not been independently security-reviewed; see the project README for
 * guidance on when a vetted library (Microsoft SEAL, OpenFHE, HElib, Lattigo) should be used
 * instead.
 */
public final class DghvCipher {
    private DghvCipher() {}

    /** Deterministically derives a secret key from a passphrase, so it can be re-derived later for decryption. */
    public static FheSecretKey keyGen(String passphrase, FheSecurityProfile profile) {
        DeterministicKeyStream stream = new DeterministicKeyStream(passphrase, "dghv-secret-key-p");
        BigInteger p = stream.nextBigInteger(profile.getEtaBits()).or(BigInteger.ONE);
        return new FheSecretKey(p, profile);
    }

    /** Encrypts a single plaintext bit (0 or 1). Encryption is probabilistic: encrypting the same bit twice yields different ciphertexts. */
    public static BigInteger encryptBit(int bit, FheSecretKey key, SecureRandom random) {
        if (bit != 0 && bit != 1) {
            throw new IllegalArgumentException("bit must be 0 or 1, got " + bit);
        }
        FheSecurityProfile profile = key.getProfile();
        int qBits = profile.getGammaBits() - profile.getEtaBits();
        BigInteger q = new BigInteger(qBits, random).setBit(qBits - 1);
        BigInteger r = new BigInteger(profile.getRhoBits(), random);
        if (random.nextBoolean()) {
            r = r.negate();
        }
        return key.getP().multiply(q)
                .add(BigInteger.TWO.multiply(r))
                .add(BigInteger.valueOf(bit));
    }

    /** Decrypts a single ciphertext back to its plaintext bit (0 or 1). */
    public static int decryptBit(BigInteger ciphertext, FheSecretKey key) {
        BigInteger p = key.getP();
        // BigInteger.mod() always returns a representative in [0, p). Since the noise term
        // 2r+m can be negative (r is signed), that representative is sometimes p + (2r+m)
        // rather than 2r+m itself. Because p is odd, adding p flips the parity bit, so we must
        // re-center the remainder into (-p/2, p/2] before reading off the parity.
        BigInteger remainder = ciphertext.mod(p);
        if (remainder.compareTo(p.shiftRight(1)) > 0) {
            remainder = remainder.subtract(p);
        }
        return remainder.mod(BigInteger.TWO).intValueExact();
    }

    /**
     * Homomorphic XOR: decrypting {@code result} yields the XOR of the two input plaintext bits,
     * provided accumulated noise has not exceeded the scheme's noise budget.
     */
    public static BigInteger homomorphicAdd(BigInteger c1, BigInteger c2) {
        return c1.add(c2);
    }

    /**
     * Homomorphic AND: decrypting {@code result} yields the AND of the two input plaintext bits,
     * provided accumulated noise has not exceeded the scheme's noise budget. Multiplication
     * grows noise much faster than addition, so chaining many of these without bootstrapping
     * will eventually produce incorrect decryptions.
     */
    public static BigInteger homomorphicMultiply(BigInteger c1, BigInteger c2) {
        return c1.multiply(c2);
    }
}
