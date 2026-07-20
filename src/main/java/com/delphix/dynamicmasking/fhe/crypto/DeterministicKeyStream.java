/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.fhe.crypto;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * A minimal HMAC-SHA256 counter-mode pseudorandom byte generator.
 *
 * <p>The DGHV secret key must be re-derivable from the same passphrase on every call
 * ({@code mask} now, {@code reidentify} later, possibly in a different process), so it cannot
 * come from {@link java.security.SecureRandom}. This class turns an arbitrary-length passphrase
 * into an arbitrary-length deterministic byte stream, which {@link DghvCipher} then shapes into
 * a key of the required bit length. This is a simplified DRBG construction (HMAC used as a PRF
 * in counter mode), not a NIST SP 800-90A compliant DRBG.
 */
final class DeterministicKeyStream {
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final Mac mac;
    private final byte[] salt;
    private long counter;
    private byte[] buffer = new byte[0];
    private int bufferOffset;

    DeterministicKeyStream(String passphrase, String salt) {
        try {
            mac = Mac.getInstance(HMAC_ALGORITHM);
            byte[] keyBytes = passphrase.getBytes(StandardCharsets.UTF_8);
            mac.init(new SecretKeySpec(keyBytes.length == 0 ? new byte[1] : keyBytes, HMAC_ALGORITHM));
            this.salt = salt.getBytes(StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("HmacSHA256 must be available on the JVM", e);
        }
    }

    /** Returns the next {@code count} pseudorandom bytes from the stream. */
    byte[] next(int count) {
        byte[] result = new byte[count];
        int produced = 0;
        while (produced < count) {
            if (bufferOffset >= buffer.length) {
                refill();
            }
            int available = buffer.length - bufferOffset;
            int toCopy = Math.min(available, count - produced);
            System.arraycopy(buffer, bufferOffset, result, produced, toCopy);
            bufferOffset += toCopy;
            produced += toCopy;
        }
        return result;
    }

    /** Returns a deterministic BigInteger with exactly {@code bits} bits, with the top bit set. */
    BigInteger nextBigInteger(int bits) {
        int byteLen = (bits + 7) / 8;
        byte[] raw = next(byteLen);
        BigInteger value = new BigInteger(1, raw);
        // Force the exact bit length so callers get the size they asked for.
        value = value.mod(BigInteger.ONE.shiftLeft(bits));
        value = value.setBit(bits - 1);
        return value;
    }

    private void refill() {
        ByteBuffer counterBlock = ByteBuffer.allocate(salt.length + Long.BYTES);
        counterBlock.put(salt);
        counterBlock.putLong(counter++);
        mac.update(counterBlock.array());
        buffer = mac.doFinal();
        bufferOffset = 0;
    }
}
