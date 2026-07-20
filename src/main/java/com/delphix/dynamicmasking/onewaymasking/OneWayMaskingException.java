/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

/** Unchecked so it can surface cleanly through the MaskingAlgorithm.mask() signature. */
public class OneWayMaskingException extends RuntimeException {
    public OneWayMaskingException(String m) {
        super(m);
    }

    public OneWayMaskingException(String m, Throwable t) {
        super(m, t);
    }
}
