/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.List;
import java.util.Random;

/**
 * Deterministic, keyed building blocks shared by the lookup/segment-mapping one-way schemes: an
 * index into a bounded range, and a shuffle of a list, both derived from HMAC-SHA256(key, ...) so
 * the same key always produces the same index/ordering. HMAC-SHA256 (unlike the AES ciphers used
 * by {@code com.delphix.dynamicmasking.tokenization}) accepts any non-empty key length, so
 * these helpers don't constrain the key to 16/24/32 bytes.
 */
final class KeyedLookup {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private KeyedLookup() {}

    static void requireNonEmptyKey(byte[] key) {
        if (key == null || key.length == 0) {
            throw new OneWayMaskingException("Key must not be null or empty");
        }
    }

    /** Deterministic index in [0, bound) derived from HMAC-SHA256(key, salt + ":" + value). */
    static int index(byte[] key, String salt, String value, int bound) {
        byte[] digest = hmac(key, salt + ":" + value);
        long unsigned = ((digest[0] & 0xFFL) << 24)
                | ((digest[1] & 0xFFL) << 16)
                | ((digest[2] & 0xFFL) << 8)
                | (digest[3] & 0xFFL);
        return (int) (unsigned % bound);
    }

    /** Deterministic Fisher-Yates shuffle of {@code list}, seeded from HMAC-SHA256(key, salt). */
    static <T> void shuffle(byte[] key, String salt, List<T> list) {
        byte[] seedBytes = hmac(key, salt);
        long seed = 0;
        for (int i = 0; i < 8; i++) {
            seed = (seed << 8) | (seedBytes[i] & 0xFF);
        }
        Collections.shuffle(list, new Random(seed));
    }

    private static byte[] hmac(byte[] key, String message) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            return mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new OneWayMaskingException("HMAC computation failed", e);
        }
    }
}
