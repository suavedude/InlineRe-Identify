/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.tokenization;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import com.delphix.dynamicmasking.tokenization.spi.CryptoProvider;
import com.delphix.dynamicmasking.tokenization.spi.TokenizationScheme;
import com.delphix.dynamicmasking.tokenization.spi.TokenizationSchemeFactory;

/**
 * Built-in {@code "AES-GCM"} algorithm: authenticated, non-deterministic AES tokenization. Each
 * {@link TokenizationScheme#tokenize} call generates a fresh random 12-byte nonce, prepended to
 * the ciphertext+tag before Base64 encoding, rather than reusing a fixed IV like {@code
 * AES-CBC-CTS} does -- so the same input produces a different token every time. This does NOT
 * preserve referential integrity across rows/tables (unlike the deterministic default), but it
 * is authenticated (a tampered or truncated token fails to decrypt rather than silently
 * corrupting) and never leaks value-equality between tokens. Accepts any valid AES key length
 * (16/24/32 bytes for AES-128/192/256).
 */
public final class AesGcmSchemeFactory implements TokenizationSchemeFactory {

    @Override
    public String id() {
        return "AES-GCM";
    }

    @Override
    public TokenizationScheme create(CryptoProvider provider) {
        return new AesGcmScheme(provider.name());
    }

    private static final class AesGcmScheme implements TokenizationScheme {

        private static final String TRANSFORMATION = "AES/GCM/NoPadding";
        private static final int NONCE_LEN = 12; // 96-bit GCM nonce, per NIST SP 800-38D
        private static final int TAG_LEN_BITS = 128;

        private final String providerName;

        AesGcmScheme(String providerName) {
            this.providerName = providerName;
        }

        @Override
        public String tokenize(String value, byte[] dek) {
            if (value == null) {
                return null;
            }
            TokenCipher.requireValidKeyLength(dek);
            try {
                byte[] nonce = new byte[NONCE_LEN];
                new SecureRandom().nextBytes(nonce);
                Cipher c = Cipher.getInstance(TRANSFORMATION, providerName);
                c.init(Cipher.ENCRYPT_MODE, keySpec(dek), new GCMParameterSpec(TAG_LEN_BITS, nonce));
                byte[] ct = c.doFinal(value.getBytes(StandardCharsets.UTF_8));
                ByteBuffer buf = ByteBuffer.allocate(NONCE_LEN + ct.length);
                buf.put(nonce).put(ct);
                return Base64.getUrlEncoder().withoutPadding().encodeToString(buf.array());
            } catch (Exception e) {
                // Never include the unmasked input in the message (it would leak to logs).
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
                byte[] raw = Base64.getUrlDecoder().decode(token);
                if (raw.length < NONCE_LEN) {
                    throw new TokenCipher.TokenizationException("Token is shorter than the GCM nonce");
                }
                byte[] nonce = Arrays.copyOfRange(raw, 0, NONCE_LEN);
                byte[] ct = Arrays.copyOfRange(raw, NONCE_LEN, raw.length);
                Cipher c = Cipher.getInstance(TRANSFORMATION, providerName);
                c.init(Cipher.DECRYPT_MODE, keySpec(dek), new GCMParameterSpec(TAG_LEN_BITS, nonce));
                byte[] pt = c.doFinal(ct);
                return new String(pt, StandardCharsets.UTF_8);
            } catch (TokenCipher.TokenizationException e) {
                throw e;
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
