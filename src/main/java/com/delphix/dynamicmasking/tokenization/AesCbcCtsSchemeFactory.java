/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.tokenization;

import java.nio.charset.StandardCharsets;

import com.delphix.dynamicmasking.tokenization.spi.CryptoProvider;
import com.delphix.dynamicmasking.tokenization.spi.TokenizationScheme;
import com.delphix.dynamicmasking.tokenization.spi.TokenizationSchemeFactory;

/**
 * Built-in {@code "AES-CBC-CTS"} algorithm: deterministic AES tokenization (see {@link
 * TokenCipher}/{@link ShortValueCipher}). Accepts any valid AES key length (16/24/32 bytes for
 * AES-128/192/256) -- the key size, not the algorithm id, selects the AES variant. Default.
 */
public final class AesCbcCtsSchemeFactory implements TokenizationSchemeFactory {

    @Override
    public String id() {
        return "AES-CBC-CTS";
    }

    @Override
    public TokenizationScheme create(CryptoProvider provider) {
        return new AesCbcCtsScheme(provider.name());
    }

    private static final class AesCbcCtsScheme implements TokenizationScheme {

        private static final char LONG_VALUE_MARKER = 'L';
        private static final char SHORT_VALUE_MARKER = 'S';

        private final String providerName;

        AesCbcCtsScheme(String providerName) {
            this.providerName = providerName;
        }

        @Override
        public String tokenize(String value, byte[] dek) {
            if (value == null) {
                return null;
            }
            int byteLength = value.getBytes(StandardCharsets.UTF_8).length;
            if (byteLength < TokenCipher.BLOCK_LEN) {
                return SHORT_VALUE_MARKER + new ShortValueCipher(dek, providerName).tokenize(value);
            }
            return LONG_VALUE_MARKER + new TokenCipher(dek, providerName).tokenize(value);
        }

        @Override
        public String detokenize(String token, byte[] dek) {
            if (token == null) {
                return null;
            }
            if (token.isEmpty()) {
                throw new TokenCipher.TokenizationException("Token is missing its mode marker");
            }
            char marker = token.charAt(0);
            String body = token.substring(1);
            if (marker == SHORT_VALUE_MARKER) {
                return new ShortValueCipher(dek, providerName).detokenize(body);
            }
            if (marker == LONG_VALUE_MARKER) {
                return new TokenCipher(dek, providerName).detokenize(body);
            }
            throw new TokenCipher.TokenizationException("Unrecognized token mode marker: " + marker);
        }
    }
}
