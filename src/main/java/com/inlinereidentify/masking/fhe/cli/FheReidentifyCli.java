/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.inlinereidentify.masking.fhe.cli;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import com.inlinereidentify.masking.fhe.crypto.DghvCipher;
import com.inlinereidentify.masking.fhe.crypto.FheSecretKey;
import com.inlinereidentify.masking.fhe.crypto.FheSecurityProfile;
import com.inlinereidentify.masking.fhe.crypto.FheStringCodec;

/**
 * Standalone command-line decryptor for tokens produced by
 * {@code FullyHomomorphicEncryptionAlgorithm} when it runs inside the Delphix masking engine.
 *
 * <p>This exists so re-identification doesn't require running the masking engine at all: given
 * the same {@code secretPassphrase}/{@code securityProfile} that were configured on the masking
 * algorithm instance, this tool re-derives the same DGHV secret key and decrypts tokens directly,
 * using exactly the same {@link DghvCipher}/{@link FheStringCodec} code the plugin uses.
 *
 * <p>Usage:
 * <pre>
 * java -cp inlineFhe.jar:masking-extensibility-api-&lt;ver&gt;.jar \
 *     com.inlinereidentify.masking.fhe.cli.FheReidentifyCli \
 *     [--profile COMPACT|HARDENED] [--passphrase &lt;secret&gt;] [--in tokens.txt] [--out plaintext.txt]
 * </pre>
 *
 * <p>The passphrase should normally come from the {@code FHE_SECRET_PASSPHRASE} environment
 * variable rather than {@code --passphrase}, to avoid leaking it through shell history or the
 * process list. Input defaults to stdin, output to stdout, one token/value per line.
 */
public final class FheReidentifyCli {
    private FheReidentifyCli() {}

    public static void main(String[] args) throws IOException {
        Options options = Options.parse(args);
        if (options.passphrase == null || options.passphrase.isEmpty()) {
            System.err.println("No passphrase provided. Set FHE_SECRET_PASSPHRASE or pass --passphrase.");
            System.exit(2);
            return;
        }

        FheSecretKey key = DghvCipher.keyGen(options.passphrase, options.profile);

        try (BufferedReader reader = openReader(options.inFile);
                Writer writer = openWriter(options.outFile)) {
            int lineNumber = 0;
            int failures = 0;
            String line;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                String token = line.trim();
                if (token.isEmpty()) {
                    continue;
                }
                try {
                    writer.write(FheStringCodec.decrypt(token, key));
                    writer.write(System.lineSeparator());
                } catch (RuntimeException e) {
                    failures++;
                    System.err.println("Line " + lineNumber + ": failed to decrypt (" + e.getMessage() + ")");
                }
            }
            if (failures > 0) {
                System.err.println(failures + " line(s) failed to decrypt.");
                System.exit(1);
            }
        }
    }

    private static BufferedReader openReader(String inFile) throws IOException {
        if (inFile == null) {
            return new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        }
        return Files.newBufferedReader(Paths.get(inFile), StandardCharsets.UTF_8);
    }

    private static Writer openWriter(String outFile) throws IOException {
        if (outFile == null) {
            return new BufferedWriter(new OutputStreamWriter(System.out, StandardCharsets.UTF_8));
        }
        return Files.newBufferedWriter(Paths.get(outFile), StandardCharsets.UTF_8);
    }

    private static final class Options {
        String passphrase = System.getenv("FHE_SECRET_PASSPHRASE");
        FheSecurityProfile profile = FheSecurityProfile.COMPACT;
        String inFile;
        String outFile;

        static Options parse(String[] args) {
            Options options = new Options();
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "--passphrase":
                        options.passphrase = requireValue(args, ++i, "--passphrase");
                        break;
                    case "--profile":
                        options.profile = FheSecurityProfile.valueOf(requireValue(args, ++i, "--profile"));
                        break;
                    case "--in":
                        options.inFile = requireValue(args, ++i, "--in");
                        break;
                    case "--out":
                        options.outFile = requireValue(args, ++i, "--out");
                        break;
                    default:
                        throw new IllegalArgumentException("Unrecognized argument: " + args[i]);
                }
            }
            return options;
        }

        private static String requireValue(String[] args, int index, String flag) {
            if (index >= args.length) {
                throw new IllegalArgumentException(flag + " requires a value");
            }
            return args[index];
        }
    }
}
