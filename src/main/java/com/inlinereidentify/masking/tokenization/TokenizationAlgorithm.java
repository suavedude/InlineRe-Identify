/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.inlinereidentify.masking.tokenization;

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
import com.inlinereidentify.masking.tokenization.key.KeyFileResolver;
import com.inlinereidentify.masking.tokenization.spi.CryptoProvider;
import com.inlinereidentify.masking.tokenization.spi.CryptoProviderRegistry;
import com.inlinereidentify.masking.tokenization.spi.TokenizationScheme;
import com.inlinereidentify.masking.tokenization.spi.TokenizationSchemeRegistry;

/**
 * A Delphix masking algorithm that deterministically tokenizes string values under a pluggable
 * crypto provider and cipher algorithm (see {@code com.inlinereidentify.masking.tokenization.spi}),
 * and reverses the token back to the original value during re-identification.
 *
 * <p>Both the crypto provider (which JCE {@code Security} provider performs the cipher
 * operations, e.g. {@code BCFIPS} or {@code SunJCE}) and the cipher algorithm (the tokenization
 * scheme itself, e.g. {@code AES-CBC-CTS}) are selected by name at runtime via {@link
 * CryptoProviderRegistry} / {@link TokenizationSchemeRegistry} rather than hardcoded, and new
 * ones can be added without touching this class -- see the registries' javadoc for the {@link
 * java.util.ServiceLoader} extension mechanism.
 *
 * <p>The default {@code AES-CBC-CTS} algorithm is deterministic (fixed IV): the same input
 * always produces the same token, which preserves referential integrity across rows/tables at
 * the cost of leaking value equality between tokens. Values of at least one AES block (16 UTF-8
 * bytes) are tokenized with ciphertext stealing so the token is the same length class as the
 * input; shorter values fall back to standard padded AES-CBC, recorded with a single marker
 * character so re-identification routes back to the matching cipher. See {@link TokenCipher} /
 * {@link ShortValueCipher} for the mechanics.
 *
 * <p>Configuration (injected as JSON by the masking engine):
 * <ul>
 *   <li>Exactly one of:
 *     <ul>
 *       <li>{@code dataEncryptionKeyBase64} - the key inline, Base64-encoded (16, 24, or 32
 *           bytes for the default AES-CBC-CTS).</li>
 *       <li>{@code keyFile} - a {@code FileReference} (e.g. a masking-engine file upload,
 *           {@code delphix-file://upload/<id>}) to a JSON file
 *           {@code {"dataEncryptionKeyBase64": "..."}} holding the same key. Keeps the key out
 *           of the algorithm's JSON config (visible in job exports/API responses) at the cost of
 *           needing a file uploaded alongside the config. See {@link KeyFileResolver}.</li>
 *     </ul>
 *     The same key must be configured on both the masking job (mask mode) and any job that needs
 *     to recover the original values (reidentify mode).</li>
 *   <li>{@code cryptoProvider} (optional, default {@code "BCFIPS"}) - the JCE provider id to
 *       resolve via {@link CryptoProviderRegistry}.</li>
 *   <li>{@code cipherAlgorithm} (optional, default {@code "AES-CBC-CTS"}) - the tokenization
 *       scheme id to resolve via {@link TokenizationSchemeRegistry}.</li>
 * </ul>
 */
public class TokenizationAlgorithm implements MaskingAlgorithm<String> {

    private String dataEncryptionKeyBase64;
    private String cryptoProvider = "BCFIPS";
    private String cipherAlgorithm = "AES-CBC-CTS";

    @JsonProperty("keyFile")
    @JsonPropertyDescription(
            "Reference to a JSON file ({\"dataEncryptionKeyBase64\": \"...\"}) holding the data "
                    + "encryption key, uploaded via the masking engine's file upload. Alternative "
                    + "to dataEncryptionKeyBase64; exactly one of the two must be set.")
    public FileReference keyFile;

    private volatile MaskingMode maskingMode = MaskingMode.MASK;
    private volatile TokenizationScheme scheme;
    /** Populated by {@link #setup} when {@link #keyFile} is configured; null otherwise. */
    private volatile byte[] resolvedFileKey;

    public String getDataEncryptionKeyBase64() {
        return dataEncryptionKeyBase64;
    }

    public void setDataEncryptionKeyBase64(String dataEncryptionKeyBase64) {
        this.dataEncryptionKeyBase64 = dataEncryptionKeyBase64;
    }

    public String getCryptoProvider() {
        return cryptoProvider;
    }

    public void setCryptoProvider(String cryptoProvider) {
        this.cryptoProvider = cryptoProvider;
    }

    public String getCipherAlgorithm() {
        return cipherAlgorithm;
    }

    public void setCipherAlgorithm(String cipherAlgorithm) {
        this.cipherAlgorithm = cipherAlgorithm;
    }

    @Override
    public String getName() {
        return "Tokenization (pluggable provider/algorithm)";
    }

    @Override
    public String getDescription() {
        return "Deterministically tokenizes/detokenizes string values using a configurable crypto provider and cipher algorithm.";
    }

    @Override
    public void validate() throws ComponentConfigurationException {
        requireExactlyOneKeySource();
        TokenizationScheme resolved;
        try {
            resolved = resolveScheme();
        } catch (IllegalArgumentException e) {
            throw new ComponentConfigurationException(e.getMessage(), e);
        }
        if (keyFile != null) {
            // Reference-syntax validation only: actually opening the file needs
            // ComponentService, which isn't available here -- see setup() below, where the
            // file-based key path gets the same self-test this does for the inline key path.
            GenericReference.checkOptionalReference(keyFile, "keyFile");
            return;
        }
        selfTest(resolved, decodeKey());
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

    /**
     * Round-trips a probe value through the resolved scheme so bad configuration (wrong key
     * length, provider that can't perform the transformation, etc.) surfaces here rather than on
     * the first row of a real job. Deliberately generic -- it doesn't assume anything about the
     * key shape a given scheme wants, so a differently-keyed algorithm plugin (e.g. one needing
     * a key+tweak pair rather than a bare AES key) is validated the same way.
     */
    private void selfTest(TokenizationScheme resolved, byte[] dek) throws ComponentConfigurationException {
        String probe = "tokenization-config-self-test";
        String recovered;
        try {
            recovered = resolved.detokenize(resolved.tokenize(probe, dek), dek);
        } catch (RuntimeException e) {
            throw new ComponentConfigurationException(
                    "dataEncryptionKeyBase64 / cryptoProvider / cipherAlgorithm failed a self-test: " + e.getMessage(), e);
        }
        if (!probe.equals(recovered)) {
            throw new ComponentConfigurationException(
                    "Configured cipherAlgorithm did not round-trip a self-test value; check dataEncryptionKeyBase64.");
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
        try {
            selfTest(resolveScheme(), resolvedFileKey);
        } catch (ComponentConfigurationException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public void setMaskingMode(MaskingMode maskingMode) {
        this.maskingMode = maskingMode;
    }

    @Override
    public String mask(String value) throws MaskingException {
        if (value == null) {
            return null;
        }
        byte[] dek = resolveKeyUnchecked();
        try {
            TokenizationScheme scheme = resolveScheme();
            if (maskingMode == MaskingMode.REIDENTIFY) {
                return scheme.detokenize(value, dek);
            }
            return scheme.tokenize(value, dek);
        } catch (RuntimeException e) {
            throw new MaskingException("Tokenization operation failed", e);
        }
    }

    /**
     * Resolves and caches the configured scheme. Not synchronized: resolution is deterministic
     * and {@link TokenizationScheme} instances are stateless per call, so a benign race that
     * resolves twice on first use is harmless.
     */
    private TokenizationScheme resolveScheme() {
        TokenizationScheme resolved = scheme;
        if (resolved == null) {
            CryptoProvider provider = CryptoProviderRegistry.resolve(cryptoProvider);
            resolved = TokenizationSchemeRegistry.resolve(cipherAlgorithm, provider);
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
                    "dataEncryptionKeyBase64 must be set to a Base64-encoded key for the configured cipherAlgorithm.");
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
            throw new MaskingException("Invalid tokenization key configuration", e);
        }
    }
}
