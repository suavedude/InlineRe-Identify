/*
 * Copyright (c) 2026 by Delphix. All rights reserved.
 */
package com.delphix.dynamicmasking.tokenization.key;

/**
 * JSON schema for a {@code keyFile}-referenced key (see {@link KeyFileResolver}):
 *
 * <pre>{@code
 * { "dataEncryptionKeyBase64": "..." }
 * }</pre>
 *
 * Kept as its own small class rather than parsed ad hoc so the schema has one place to grow if
 * it ever needs a second field (e.g. a key id/version for rotation).
 */
final class KeyFile {
    public String dataEncryptionKeyBase64;
}
