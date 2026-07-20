/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.tokenization.key;

import java.util.Base64;
import java.util.Locale;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;

/**
 * Resolves the data encryption key (DEK) shared by every standalone tokenization entry point
 * (the Redshift Lambda UDF handler, the plain HTTP API server) -- not used by the Delphix
 * plugin, which gets its key directly from job config instead of the environment.
 *
 * <p>Two modes, selected by the {@code KEY_SOURCE} environment variable:
 * <ul>
 *   <li>{@code KMS} (default, for real deployments) - {@code DATA_ENCRYPTION_KEY_CIPHERTEXT_BASE64}
 *       holds the DEK encrypted under an AWS KMS parent/customer master key (envelope
 *       encryption). Resolved once per process (Lambda execution environment, or HTTP server
 *       startup) via KMS {@code Decrypt} and cached in memory for that process's life -- the
 *       plaintext DEK is never logged or written to disk, and the parent key never leaves KMS.</li>
 *   <li>{@code PLAINTEXT} (local/dev only, e.g. the docker-compose stack against a local
 *       Postgres) - {@code DATA_ENCRYPTION_KEY_BASE64} holds the raw Base64 DEK directly, no KMS
 *       call required.</li>
 * </ul>
 */
public final class DataEncryptionKeySource {

    private DataEncryptionKeySource() {}

    public static byte[] resolve() {
        String source = System.getenv().getOrDefault("KEY_SOURCE", "KMS").toUpperCase(Locale.ROOT);
        switch (source) {
            case "PLAINTEXT":
                return Base64.getDecoder().decode(requireEnv("DATA_ENCRYPTION_KEY_BASE64"));
            case "KMS":
                return resolveViaKms();
            default:
                throw new IllegalStateException("Unsupported KEY_SOURCE: " + source + " (expected KMS or PLAINTEXT)");
        }
    }

    private static byte[] resolveViaKms() {
        byte[] ciphertext = Base64.getDecoder().decode(requireEnv("DATA_ENCRYPTION_KEY_CIPHERTEXT_BASE64"));
        try (KmsClient kms = KmsClient.create()) {
            DecryptRequest.Builder request = DecryptRequest.builder()
                    .ciphertextBlob(SdkBytes.fromByteArray(ciphertext));
            // Pin the expected parent key when set, so a ciphertext produced under (or
            // re-wrapped to) the wrong CMK fails closed instead of silently decrypting.
            String kmsKeyId = System.getenv("KMS_KEY_ID");
            if (kmsKeyId != null && !kmsKeyId.isEmpty()) {
                request.keyId(kmsKeyId);
            }
            return kms.decrypt(request.build()).plaintext().asByteArray();
        }
    }

    private static String requireEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isEmpty()) {
            throw new IllegalStateException(name + " environment variable must be set");
        }
        return value;
    }
}
