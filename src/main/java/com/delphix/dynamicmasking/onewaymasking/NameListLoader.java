/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.onewaymasking;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Loads a newline-separated name list bundled as a classpath resource under this package (see
 * {@code first-names.txt} / {@code last-names.txt}), caching each by resource name so repeated
 * scheme resolution (e.g. once per Lambda cold start) doesn't re-read the jar entry.
 */
final class NameListLoader {

    private static final Map<String, List<String>> CACHE = new ConcurrentHashMap<>();

    private NameListLoader() {}

    static List<String> load(String resourceName) {
        return CACHE.computeIfAbsent(resourceName, NameListLoader::read);
    }

    private static List<String> read(String resourceName) {
        String path = resourceName; // resolved relative to this class's package below
        try (InputStream is = NameListLoader.class.getResourceAsStream(path)) {
            if (is == null) {
                throw new OneWayMaskingException("Bundled name list resource not found: " + resourceName);
            }
            List<String> names = new ArrayList<>();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (!line.isEmpty()) {
                        names.add(line);
                    }
                }
            }
            if (names.isEmpty()) {
                throw new OneWayMaskingException("Bundled name list resource is empty: " + resourceName);
            }
            return Collections.unmodifiableList(names);
        } catch (IOException e) {
            throw new OneWayMaskingException("Failed to read bundled name list resource: " + resourceName, e);
        }
    }
}
