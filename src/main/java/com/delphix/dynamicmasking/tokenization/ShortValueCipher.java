/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.tokenization;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Fallback cipher for values shorter than one AES block (16 bytes), where
 * {@link TokenCipher}'s ciphertext-stealing mode is undefined. Same key, same provider, same
 * fixed all-zero IV (so it stays deterministic), but standard PKCS#7 padding instead of CTS --
 * this expands the token to exactly one block, which is acceptable since these are already the
 * shortest values.
 */
final class ShortValueCipher {

    // "PKCS5Padding" despite actually being PKCS7 padding (identical for any block size, AES's
    // 128 bits included): it's the name the JCE convention -- and every provider, not just BC --
    // actually registers it under. "PKCS7Padding" is a BC-only alias and fails on e.g. SunJCE.
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final byte[] ZERO_IV = new byte[TokenCipher.BLOCK_LEN];

    private final SecretKeySpec key;
    private final String providerName;

    /**
     * @param dek the AES data encryption key (16, 24, or 32 bytes for AES-128/192/256).
     * @param providerName the JCE provider to use; the caller must have already ensured it's
     *            registered (see {@link TokenCipher#TokenCipher(byte[], String)}).
     */
    ShortValueCipher(byte[] dek, String providerName) {
        TokenCipher.requireValidKeyLength(dek);
        this.providerName = providerName;
        byte[] copy = Arrays.copyOf(dek, dek.length);
        this.key = new SecretKeySpec(copy, "AES");
        Arrays.fill(copy, (byte) 0);
    }

    String tokenize(String plaintext) {
        try {
            Cipher c = Cipher.getInstance(TRANSFORMATION, providerName);
            c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ZERO_IV));
            byte[] ct = c.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(ct);
        } catch (Exception e) {
            throw new TokenCipher.TokenizationException("tokenize failed", e);
        }
    }

    String detokenize(String token) {
        try {
            byte[] ct = Base64.getUrlDecoder().decode(token);
            Cipher c = Cipher.getInstance(TRANSFORMATION, providerName);
            c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ZERO_IV));
            byte[] pt = c.doFinal(ct);
            return new String(pt, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new TokenCipher.TokenizationException("detokenize failed", e);
        }
    }
}
