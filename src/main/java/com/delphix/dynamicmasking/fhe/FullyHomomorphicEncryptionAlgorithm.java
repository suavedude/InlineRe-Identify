/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.fhe;

import java.security.SecureRandom;

import com.delphix.masking.api.plugin.MaskingAlgorithm;
import com.delphix.masking.api.plugin.exception.ComponentConfigurationException;
import com.delphix.masking.api.plugin.exception.MaskingException;
import com.delphix.dynamicmasking.fhe.crypto.DghvCipher;
import com.delphix.dynamicmasking.fhe.crypto.FheSecretKey;
import com.delphix.dynamicmasking.fhe.crypto.FheSecurityProfile;
import com.delphix.dynamicmasking.fhe.crypto.FheStringCodec;

/**
 * A Delphix masking algorithm that encrypts string values with a from-scratch implementation of
 * the DGHV fully homomorphic encryption scheme (see {@link DghvCipher}), and decrypts them again
 * during re-identification.
 *
 * <p>Configuration (injected as JSON by the masking engine):
 * <ul>
 *   <li>{@code secretPassphrase} (required) - used to deterministically derive the FHE secret
 *       key. The same passphrase must be configured on both the masking job (mask mode) and any
 *       job that needs to recover the original values (reidentify mode).</li>
 *   <li>{@code securityProfile} (optional, default {@code COMPACT}) - one of
 *       {@link FheSecurityProfile}. Controls the size/security tradeoff; must match between
 *       encryption and decryption.</li>
 * </ul>
 *
 * <p>This algorithm is intended for evaluating FHE-based tokenization within the masking
 * pipeline. It has not been independently security-audited - see the project README before
 * using it to protect real sensitive data.
 */
public class FullyHomomorphicEncryptionAlgorithm implements MaskingAlgorithm<String> {
    private final SecureRandom random = new SecureRandom();

    private String secretPassphrase;
    private String securityProfile = FheSecurityProfile.COMPACT.name();

    private volatile MaskingMode maskingMode = MaskingMode.MASK;

    public String getSecretPassphrase() {
        return secretPassphrase;
    }

    public void setSecretPassphrase(String secretPassphrase) {
        this.secretPassphrase = secretPassphrase;
    }

    public String getSecurityProfile() {
        return securityProfile;
    }

    public void setSecurityProfile(String securityProfile) {
        this.securityProfile = securityProfile;
    }

    @Override
    public String getName() {
        return "Fully Homomorphic Encryption (DGHV)";
    }

    @Override
    public String getDescription() {
        return "Encrypts/decrypts string values using a DGHV fully homomorphic encryption scheme over the integers.";
    }

    @Override
    public void validate() throws ComponentConfigurationException {
        if (secretPassphrase == null || secretPassphrase.isEmpty()) {
            throw new ComponentConfigurationException(
                    "secretPassphrase must be set to a non-empty value used to derive the FHE secret key.");
        }
        try {
            FheSecurityProfile.valueOf(securityProfile);
        } catch (IllegalArgumentException e) {
            throw new ComponentConfigurationException(
                    "securityProfile must be one of " + java.util.Arrays.toString(FheSecurityProfile.values()), e);
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
        FheSecretKey key = DghvCipher.keyGen(secretPassphrase, FheSecurityProfile.valueOf(securityProfile));
        try {
            if (maskingMode == MaskingMode.REIDENTIFY) {
                return FheStringCodec.decrypt(value, key);
            }
            return FheStringCodec.encrypt(value, key, random);
        } catch (RuntimeException e) {
            throw new MaskingException("Fully homomorphic encryption operation failed", e);
        }
    }
}
