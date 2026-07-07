/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.inlinereidentify.masking.tokenization;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Set;

/**
 * Deterministic, reversible token cipher used by the {@code "AES-CBC-CTS"} {@link
 * com.inlinereidentify.masking.tokenization.spi.TokenizationScheme} (see {@link
 * AesCbcCtsSchemeFactory}).
 *
 * Crypto contract (every value below is parity-critical -- change it and existing tokens stop
 * reversing):
 *   - AES-128/192/256 (16/24/32-byte DEK; the key length selects the variant)
 *   - CBC mode with ciphertext stealing (CTS), so the token is the same length class
 *     as the input and no padding block is added
 *   - FIXED ALL-ZERO IV  => deterministic: same plaintext always yields the same token.
 *     This is what makes a bare token reversible from the token + DEK alone, with no
 *     per-value IV to store. Tradeoff: equal plaintexts produce equal tokens (the token
 *     set leaks value-equality / frequency). Accepted deliberately for referential
 *     integrity. Do NOT switch to a random IV unless you also persist the IV per token.
 *   - Base64 (URL-safe, unpadded) of the raw ciphertext bytes
 *
 * The security provider used for {@code Cipher.getInstance} is injected at construction (see
 * {@link com.inlinereidentify.masking.tokenization.spi.CryptoProvider}) rather than hardcoded,
 * so this class is provider-agnostic; provider registration is that provider's responsibility,
 * not this class's.
 *
 * CTS is undefined below one AES block (16 bytes); inputs shorter than that are routed by
 * {@link AesCbcCtsSchemeFactory} to {@link ShortValueCipher} instead.
 */
public final class TokenCipher {

    private static final String TRANSFORMATION = "AES/CBC/CS3Padding";
    static final int BLOCK_LEN = 16; // AES block; CTS needs >= 1 block
    private static final byte[] ZERO_IV = new byte[BLOCK_LEN]; // all zeros

    /** Valid AES key lengths in bytes: 128/192/256-bit. */
    static final Set<Integer> VALID_KEY_LENGTHS = Set.of(16, 24, 32);

    private final SecretKeySpec key;
    private final String providerName;

    /**
     * @param dek the AES data encryption key (16, 24, or 32 bytes for AES-128/192/256). A
     *            defensive copy is taken; the caller should zeroize its own array.
     * @param providerName the JCE provider to use, e.g. {@code "BCFIPS"} or {@code "SunJCE"}
     *            (see {@link com.inlinereidentify.masking.tokenization.spi.CryptoProvider#name()}).
     *            The caller is responsible for having already ensured it's registered.
     */
    public TokenCipher(byte[] dek, String providerName) {
        requireValidKeyLength(dek);
        this.providerName = providerName;
        byte[] copy = Arrays.copyOf(dek, dek.length);
        this.key = new SecretKeySpec(copy, "AES");
        Arrays.fill(copy, (byte) 0); // SecretKeySpec already copied it internally
    }

    static void requireValidKeyLength(byte[] dek) {
        if (dek == null || !VALID_KEY_LENGTHS.contains(dek.length)) {
            throw new TokenizationException(
                    "DEK must be 16, 24, or 32 bytes (AES-128/192/256), got "
                            + (dek == null ? "null" : dek.length + " bytes"));
        }
    }

    /** Forward direction. */
    public String tokenize(String plaintext) {
        if (plaintext == null) {
            return null;
        }
        byte[] pt = plaintext.getBytes(StandardCharsets.UTF_8);
        if (pt.length < BLOCK_LEN) {
            // CTS is undefined below one block. Mirror Delphix: the caller routes short
            // values to the configured fallback algorithm rather than this cipher.
            throw new ShortInputException(
                    "Input shorter than " + BLOCK_LEN + " bytes; use the fallback algorithm");
        }
        try {
            Cipher c = Cipher.getInstance(TRANSFORMATION, providerName);
            c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ZERO_IV));
            byte[] ct = c.doFinal(pt);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(ct);
        } catch (Exception e) {
            // Never include the unmasked input in the message (it would leak to logs).
            throw new TokenizationException("tokenize failed", e);
        }
    }

    /** Reverse direction. */
    public String detokenize(String token) {
        if (token == null) {
            return null;
        }
        try {
            byte[] ct = Base64.getUrlDecoder().decode(token);
            Cipher c = Cipher.getInstance(TRANSFORMATION, providerName);
            c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ZERO_IV));
            byte[] pt = c.doFinal(ct);
            return new String(pt, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new TokenizationException("detokenize failed", e);
        }
    }

    /** Unchecked so it can surface cleanly through the MaskingAlgorithm.mask() signature. */
    public static class TokenizationException extends RuntimeException {
        public TokenizationException(String m)             { super(m); }
        public TokenizationException(String m, Throwable t) { super(m, t); }
    }

    /** Thrown for inputs too short for CTS; caller routes these to the fallback algorithm. */
    public static class ShortInputException extends TokenizationException {
        public ShortInputException(String m) { super(m); }
    }
}
