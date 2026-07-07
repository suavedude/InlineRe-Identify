/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.inlinereidentify.masking.tokenization.key;

import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Resolves a data encryption key from an uploaded JSON key file, for {@code
 * TokenizationAlgorithm}'s {@code keyFile} config field (a {@code FileReference} opened via
 * {@code ComponentService.openInputFile}) -- an alternative to passing the key inline as
 * {@code dataEncryptionKeyBase64} plugin config.
 *
 * <p>Deliberately plaintext-only: the file <em>is</em> the secret artifact (protected by upload
 * access control on the masking engine), not a pointer to a key held elsewhere. A KMS-wrapped
 * variant (matching {@code DataEncryptionKeySource}'s {@code KEY_SOURCE=KMS} mode for the
 * standalone Lambda/HTTP entry points) was deliberately left out here: it would require bundling
 * the AWS SDK into the Delphix plugin jar and assumes the engine's plugin sandbox permits
 * outbound network calls from algorithm code, neither of which is verified against a real
 * engine. Ask if you want that added once that's confirmed safe.
 */
public final class KeyFileResolver {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private KeyFileResolver() {}

    /** @throws IOException if the stream isn't valid JSON matching the {@link KeyFile} schema. */
    public static byte[] resolve(InputStream jsonInputStream) throws IOException {
        KeyFile keyFile = MAPPER.readValue(jsonInputStream, KeyFile.class);
        if (keyFile.dataEncryptionKeyBase64 == null || keyFile.dataEncryptionKeyBase64.isEmpty()) {
            throw new IOException("Key file must set 'dataEncryptionKeyBase64'");
        }
        try {
            return Base64.getDecoder().decode(keyFile.dataEncryptionKeyBase64);
        } catch (IllegalArgumentException e) {
            throw new IOException("Key file's 'dataEncryptionKeyBase64' is not valid Base64", e);
        }
    }
}
