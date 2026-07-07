/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.inlinereidentify.masking.fhe.crypto;

/**
 * Bit-size parameters for the {@link DghvCipher} scheme.
 *
 * <p>Parameter names follow the original DGHV paper (van Dijk, Gentry, Halevi, Vaikuntanathan,
 * "Fully Homomorphic Encryption over the Integers", EUROCRYPT 2010):
 * <ul>
 *   <li>{@code eta} - bit length of the secret key {@code p}</li>
 *   <li>{@code gamma} - bit length of a ciphertext</li>
 *   <li>{@code rho} - bit length of the noise {@code r}</li>
 * </ul>
 *
 * <p><b>These are not vetted, production-grade security parameters.</b> Real DGHV deployments
 * use eta/gamma values in the thousands-of-bits range to resist lattice-reduction attacks, which
 * makes per-bit ciphertexts kilobytes in size. {@link #COMPACT} trades security margin for a
 * ciphertext size that is practical to store as a masked column value; {@link #HARDENED} is
 * closer to literature-recommended sizes at the cost of much larger tokens and slower
 * encrypt/decrypt. Neither has been independently audited - see the plugin README before using
 * this for anything beyond evaluation/demo purposes.
 */
public enum FheSecurityProfile {
    COMPACT(384, 2048, 48),
    HARDENED(1536, 12288, 96);

    private final int etaBits;
    private final int gammaBits;
    private final int rhoBits;

    FheSecurityProfile(int etaBits, int gammaBits, int rhoBits) {
        this.etaBits = etaBits;
        this.gammaBits = gammaBits;
        this.rhoBits = rhoBits;
    }

    public int getEtaBits() {
        return etaBits;
    }

    public int getGammaBits() {
        return gammaBits;
    }

    public int getRhoBits() {
        return rhoBits;
    }
}
