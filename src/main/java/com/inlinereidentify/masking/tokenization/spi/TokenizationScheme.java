/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.inlinereidentify.masking.tokenization.spi;

/**
 * A reversible tokenization algorithm bound to a specific {@link CryptoProvider}. Owns its own
 * wire format end to end (e.g. mode markers, IV handling) -- callers just pass the key.
 */
public interface TokenizationScheme {

    /** @return null if {@code value} is null; otherwise a token that {@link #detokenize} reverses. */
    String tokenize(String value, byte[] key);

    /** @return null if {@code token} is null; otherwise the original value passed to {@link #tokenize}. */
    String detokenize(String token, byte[] key);
}
