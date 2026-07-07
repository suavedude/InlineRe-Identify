/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.inlinereidentify.masking.fhe.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.List;

import com.inlinereidentify.masking.fhe.crypto.DghvCipher;
import com.inlinereidentify.masking.fhe.crypto.FheSecretKey;
import com.inlinereidentify.masking.fhe.crypto.FheSecurityProfile;
import com.inlinereidentify.masking.fhe.crypto.FheStringCodec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FheReidentifyCliTest {
    @TempDir
    Path tempDir;

    @Test
    void decryptsTokensFromFileToFileGivenMatchingPassphraseAndProfile() throws IOException {
        FheSecretKey key = DghvCipher.keyGen("cli-test-passphrase", FheSecurityProfile.COMPACT);
        SecureRandom random = new SecureRandom();
        String first = FheStringCodec.encrypt("alpha value", key, random);
        String second = FheStringCodec.encrypt("beta value", key, random);

        Path in = tempDir.resolve("tokens.txt");
        Path out = tempDir.resolve("plaintext.txt");
        Files.write(in, List.of(first, second), StandardCharsets.UTF_8);

        FheReidentifyCli.main(new String[] {
                "--passphrase", "cli-test-passphrase",
                "--profile", "COMPACT",
                "--in", in.toString(),
                "--out", out.toString()
        });

        List<String> decrypted = Files.readAllLines(out, StandardCharsets.UTF_8);
        assertEquals(List.of("alpha value", "beta value"), decrypted);
    }
}
