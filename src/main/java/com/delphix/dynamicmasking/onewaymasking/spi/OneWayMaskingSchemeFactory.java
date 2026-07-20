/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking.spi;

/**
 * Extension point for adding a new one-way masking algorithm without touching this module's
 * source: drop a jar on the classpath containing an implementation of this interface plus a
 * {@code META-INF/services/com.delphix.dynamicmasking.onewaymasking.spi.OneWayMaskingSchemeFactory}
 * file naming it (standard {@link java.util.ServiceLoader} discovery), and it becomes selectable
 * via the {@code maskingScheme} plugin config field / {@code MASKING_SCHEME} Lambda/HTTP env var.
 *
 * <p>Implementations must have a public no-arg constructor.
 */
public interface OneWayMaskingSchemeFactory {

    /** Selector string matched case-insensitively against config, e.g. {@code "FIRST-NAME-LOOKUP"}. */
    String id();

    OneWayMaskingScheme create();
}
