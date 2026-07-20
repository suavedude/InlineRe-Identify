/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.fhe.crypto;

import java.math.BigInteger;

/** The DGHV symmetric secret key: an odd integer {@code p} of {@code eta} bits. */
public final class FheSecretKey {
    private final BigInteger p;
    private final FheSecurityProfile profile;

    FheSecretKey(BigInteger p, FheSecurityProfile profile) {
        this.p = p;
        this.profile = profile;
    }

    BigInteger getP() {
        return p;
    }

    public FheSecurityProfile getProfile() {
        return profile;
    }
}
