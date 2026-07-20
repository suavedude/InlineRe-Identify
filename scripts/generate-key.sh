#!/usr/bin/env bash
# Generates a random 16-byte AES-128 data encryption key (DEK) for local dev use with
# KEY_SOURCE=PLAINTEXT (see docker-compose.yml). Prints an .env-ready line.
#
# For a real KMS-backed deployment (KEY_SOURCE=KMS), wrap this same DEK under your parent CMK
# instead of using the plaintext form:
#   aws kms encrypt --key-id alias/dynamicmasking-parent-key \
#       --plaintext fileb://<(echo -n "$DEK_BASE64" | base64 -d) \
#       --query CiphertextBlob --output text
# and set DATA_ENCRYPTION_KEY_CIPHERTEXT_BASE64 to that output instead.
set -euo pipefail

DEK_BASE64=$(openssl rand -base64 16)
echo "DATA_ENCRYPTION_KEY_BASE64=${DEK_BASE64}"
