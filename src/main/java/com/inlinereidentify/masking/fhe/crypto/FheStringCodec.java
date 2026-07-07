/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.inlinereidentify.masking.fhe.crypto;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Encrypts/decrypts whole strings with {@link DghvCipher}, which only operates on individual
 * bits. A string is encoded as UTF-8 bytes, each bit of each byte is encrypted independently into
 * its own ciphertext, and the resulting ciphertexts are packed into a single Base64 token that
 * can be stored as the masked column value.
 *
 * <p>Because DGHV ciphertexts are large integers (hundreds to thousands of bytes each, one per
 * plaintext *bit*), the token for an N-character string is roughly
 * {@code 8*N*(gammaBits/8 + HEADER_SLACK_BYTES)} bytes - several orders of magnitude larger than
 * the original value. This is an inherent property of bit-wise integer FHE schemes, not a bug;
 * see the plugin README for sizing guidance.
 */
public final class FheStringCodec {
    /** Extra bytes of headroom per ciphertext block, to safely hold the optional sign byte from BigInteger encoding and the +1 bit of growth from p*q. */
    private static final int HEADER_SLACK_BYTES = 2;
    private static final int HEADER_BYTES = 1 + Integer.BYTES;

    private FheStringCodec() {}

    public static String encrypt(String plaintext, FheSecretKey key, SecureRandom random) {
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        int blockBytes = blockByteLength(key.getProfile());

        ByteBuffer out = ByteBuffer.allocate(HEADER_BYTES + plaintextBytes.length * 8 * blockBytes);
        out.put((byte) key.getProfile().ordinal());
        out.putInt(plaintextBytes.length);

        for (byte b : plaintextBytes) {
            for (int bitIndex = 7; bitIndex >= 0; bitIndex--) {
                int bit = (b >> bitIndex) & 1;
                BigInteger ciphertext = DghvCipher.encryptBit(bit, key, random);
                out.put(toFixedBytes(ciphertext, blockBytes));
            }
        }
        return Base64.getEncoder().encodeToString(out.array());
    }

    public static String decrypt(String token, FheSecretKey key) {
        byte[] data = Base64.getDecoder().decode(token);
        ByteBuffer in = ByteBuffer.wrap(data);

        int profileOrdinal = in.get() & 0xFF;
        FheSecurityProfile[] profiles = FheSecurityProfile.values();
        if (profileOrdinal < 0 || profileOrdinal >= profiles.length) {
            throw new IllegalArgumentException("Token references an unknown FHE security profile");
        }
        FheSecurityProfile tokenProfile = profiles[profileOrdinal];
        if (tokenProfile != key.getProfile()) {
            throw new IllegalArgumentException("Token was encrypted with security profile " + tokenProfile
                    + " but the configured key uses " + key.getProfile());
        }

        int plaintextLength = in.getInt();
        int blockBytes = blockByteLength(tokenProfile);
        byte[] plaintextBytes = new byte[plaintextLength];

        byte[] block = new byte[blockBytes];
        for (int byteIndex = 0; byteIndex < plaintextLength; byteIndex++) {
            int reconstructed = 0;
            for (int bitIndex = 7; bitIndex >= 0; bitIndex--) {
                in.get(block);
                BigInteger ciphertext = new BigInteger(1, block);
                int bit = DghvCipher.decryptBit(ciphertext, key);
                reconstructed |= (bit << bitIndex);
            }
            plaintextBytes[byteIndex] = (byte) reconstructed;
        }
        return new String(plaintextBytes, StandardCharsets.UTF_8);
    }

    private static int blockByteLength(FheSecurityProfile profile) {
        return profile.getGammaBits() / 8 + HEADER_SLACK_BYTES;
    }

    private static byte[] toFixedBytes(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        byte[] result = new byte[length];
        int copyLen = Math.min(raw.length, length);
        System.arraycopy(raw, raw.length - copyLen, result, length - copyLen, copyLen);
        return result;
    }
}
