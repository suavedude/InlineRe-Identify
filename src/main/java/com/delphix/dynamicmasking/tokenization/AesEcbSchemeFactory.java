/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.tokenization;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import com.delphix.dynamicmasking.tokenization.spi.CryptoProvider;
import com.delphix.dynamicmasking.tokenization.spi.TokenizationScheme;
import com.delphix.dynamicmasking.tokenization.spi.TokenizationSchemeFactory;

/**
 * Built-in {@code "AES-ECB"} algorithm: deterministic, no-IV AES tokenization -- the simplest
 * and weakest of the built-in schemes. Because ECB encrypts each 16-byte block independently
 * with no chaining, identical plaintext blocks (not just identical whole values, as with {@code
 * AES-CBC-CTS}'s fixed IV) produce identical ciphertext blocks, leaking repeated substrings
 * within and across multi-block values. Provided for legacy/interop cases that specifically
 * require unchained block encryption; prefer {@code AES-CBC-CTS} or {@code AES-GCM} otherwise.
 * Accepts any valid AES key length (16/24/32 bytes for AES-128/192/256).
 */
public final class AesEcbSchemeFactory implements TokenizationSchemeFactory {

    @Override
    public String id() {
        return "AES-ECB";
    }

    @Override
    public TokenizationScheme create(CryptoProvider provider) {
        return new AesEcbScheme(provider.name());
    }

    private static final class AesEcbScheme implements TokenizationScheme {

        private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

        private final String providerName;

        AesEcbScheme(String providerName) {
            this.providerName = providerName;
        }

        @Override
        public String tokenize(String value, byte[] dek) {
            if (value == null) {
                return null;
            }
            TokenCipher.requireValidKeyLength(dek);
            try {
                Cipher c = Cipher.getInstance(TRANSFORMATION, providerName);
                c.init(Cipher.ENCRYPT_MODE, keySpec(dek));
                byte[] ct = c.doFinal(value.getBytes(StandardCharsets.UTF_8));
                return Base64.getUrlEncoder().withoutPadding().encodeToString(ct);
            } catch (Exception e) {
                throw new TokenCipher.TokenizationException("tokenize failed", e);
            }
        }

        @Override
        public String detokenize(String token, byte[] dek) {
            if (token == null) {
                return null;
            }
            TokenCipher.requireValidKeyLength(dek);
            try {
                byte[] ct = Base64.getUrlDecoder().decode(token);
                Cipher c = Cipher.getInstance(TRANSFORMATION, providerName);
                c.init(Cipher.DECRYPT_MODE, keySpec(dek));
                byte[] pt = c.doFinal(ct);
                return new String(pt, StandardCharsets.UTF_8);
            } catch (Exception e) {
                throw new TokenCipher.TokenizationException("detokenize failed", e);
            }
        }

        private static SecretKeySpec keySpec(byte[] dek) {
            byte[] copy = Arrays.copyOf(dek, dek.length);
            SecretKeySpec spec = new SecretKeySpec(copy, "AES");
            Arrays.fill(copy, (byte) 0);
            return spec;
        }
    }
}
