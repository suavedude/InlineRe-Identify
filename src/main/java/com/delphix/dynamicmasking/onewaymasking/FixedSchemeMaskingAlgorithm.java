/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;

import javax.annotation.Nonnull;

import com.delphix.masking.api.plugin.MaskingAlgorithm;
import com.delphix.masking.api.plugin.exception.ComponentConfigurationException;
import com.delphix.masking.api.plugin.exception.MaskingException;
import com.delphix.masking.api.plugin.referenceType.FileReference;
import com.delphix.masking.api.plugin.referenceType.GenericReference;
import com.delphix.masking.api.provider.ComponentService;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingScheme;
import com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingSchemeRegistry;
import com.delphix.dynamicmasking.tokenization.key.KeyFileResolver;

/**
 * Base for a Delphix masking algorithm that applies exactly one, fixed one-way scheme -- unlike a
 * single generic "pick a scheme" algorithm, each subclass (see {@link FullNameMaskingAlgorithm},
 * {@link CreditCardMaskingAlgorithm}, {@link EmailMaskingAlgorithm}) shows up in the engine's
 * algorithm catalog under its own name, with no scheme-selector field to get wrong. There is no
 * {@code REIDENTIFY} mode: these schemes deliberately can't be reversed.
 *
 * <p>Configuration (injected as JSON by the masking engine) is just the key -- exactly one of:
 * <ul>
 *   <li>{@code dataEncryptionKeyBase64} - a key, Base64-encoded, used to derive deterministic
 *       per-value randomness (HMAC-SHA256) rather than as an AES key -- any non-empty length
 *       works, unlike the tokenization algorithm's fixed 16/24/32-byte requirement.</li>
 *   <li>{@code keyFile} - a {@code FileReference} to a JSON file {@code
 *       {"dataEncryptionKeyBase64": "..."}} holding the same key, keeping it out of the
 *       algorithm's JSON config. See {@link KeyFileResolver}.</li>
 * </ul>
 * Static-redaction-style schemes ignore the key, but one must still be configured for uniformity.
 */
abstract class FixedSchemeMaskingAlgorithm implements MaskingAlgorithm<String> {

    private String dataEncryptionKeyBase64;

    @JsonProperty("keyFile")
    @JsonPropertyDescription(
            "Reference to a JSON file ({\"dataEncryptionKeyBase64\": \"...\"}) holding the "
                    + "masking key, uploaded via the masking engine's file upload. Alternative to "
                    + "dataEncryptionKeyBase64; exactly one of the two must be set.")
    public FileReference keyFile;

    private volatile OneWayMaskingScheme scheme;
    /** Populated by {@link #setup} when {@link #keyFile} is configured; null otherwise. */
    private volatile byte[] resolvedFileKey;

    /** The fixed scheme id this algorithm always runs -- see {@link OneWayMaskingSchemeRegistry}. */
    abstract String schemeId();

    public String getDataEncryptionKeyBase64() {
        return dataEncryptionKeyBase64;
    }

    public void setDataEncryptionKeyBase64(String dataEncryptionKeyBase64) {
        this.dataEncryptionKeyBase64 = dataEncryptionKeyBase64;
    }

    @Override
    public void validate() throws ComponentConfigurationException {
        requireExactlyOneKeySource();
        try {
            resolveScheme();
        } catch (IllegalArgumentException e) {
            throw new ComponentConfigurationException(e.getMessage(), e);
        }
        if (keyFile != null) {
            // Reference-syntax validation only: actually opening the file needs
            // ComponentService, which isn't available here -- see setup() below.
            GenericReference.checkOptionalReference(keyFile, "keyFile");
            return;
        }
        decodeKey();
    }

    private void requireExactlyOneKeySource() throws ComponentConfigurationException {
        boolean hasInlineKey = dataEncryptionKeyBase64 != null && !dataEncryptionKeyBase64.isEmpty();
        boolean hasKeyFile = keyFile != null;
        if (hasInlineKey == hasKeyFile) {
            throw new ComponentConfigurationException(
                    "Exactly one of dataEncryptionKeyBase64 or keyFile must be set, not "
                            + (hasInlineKey ? "both" : "neither") + ".");
        }
    }

    @Override
    public void setup(@Nonnull ComponentService serviceProvider) {
        if (keyFile == null) {
            return;
        }
        try (InputStream is = serviceProvider.openInputFile(keyFile)) {
            resolvedFileKey = KeyFileResolver.resolve(is);
        } catch (IOException e) {
            throw new RuntimeException("Unable to read/parse keyFile", e);
        }
    }

    @Override
    public String mask(String value) throws MaskingException {
        if (value == null) {
            return null;
        }
        byte[] key = resolveKeyUnchecked();
        try {
            return resolveScheme().mask(value, key);
        } catch (RuntimeException e) {
            throw new MaskingException("One-way masking operation failed", e);
        }
    }

    /**
     * Resolves and caches the fixed scheme. Not synchronized: resolution is deterministic and
     * {@link OneWayMaskingScheme} instances are stateless per call, so a benign race that
     * resolves twice on first use is harmless.
     */
    private OneWayMaskingScheme resolveScheme() {
        OneWayMaskingScheme resolved = scheme;
        if (resolved == null) {
            resolved = OneWayMaskingSchemeRegistry.resolve(schemeId());
            scheme = resolved;
        }
        return resolved;
    }

    private byte[] resolveKeyUnchecked() throws MaskingException {
        if (keyFile != null) {
            byte[] fileKey = resolvedFileKey;
            if (fileKey == null) {
                throw new MaskingException(
                        "keyFile is configured but has not been resolved -- setup() must run before mask()");
            }
            return fileKey;
        }
        return decodeKeyUnchecked();
    }

    private byte[] decodeKey() throws ComponentConfigurationException {
        if (dataEncryptionKeyBase64 == null || dataEncryptionKeyBase64.isEmpty()) {
            throw new ComponentConfigurationException(
                    "dataEncryptionKeyBase64 must be set to a Base64-encoded key.");
        }
        try {
            return Base64.getDecoder().decode(dataEncryptionKeyBase64);
        } catch (IllegalArgumentException e) {
            throw new ComponentConfigurationException("dataEncryptionKeyBase64 is not valid Base64.", e);
        }
    }

    private byte[] decodeKeyUnchecked() throws MaskingException {
        try {
            return decodeKey();
        } catch (ComponentConfigurationException e) {
            throw new MaskingException("Invalid masking key configuration", e);
        }
    }
}
