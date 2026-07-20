#!/usr/bin/env bash
# Produces what's needed to keep a Delphix Continuous Compliance engine's algorithm instance in
# sync with this repo's standalone AWS deployment (Lambda UDF / HTTP server), so tokens/masked
# values match regardless of which side produced them. See README.md's "Keeping the Delphix
# engine in sync" section for the full design -- short version:
#
#   1. The plaintext DEK in .env (DATA_ENCRYPTION_KEY_BASE64) is the single source of truth.
#      Never let the engine and the standalone deployment hold independently-generated keys.
#   2. This script turns that DEK into the exact keyFile JSON the engine's algorithm config
#      expects (see TokenizationAlgorithm / OneWayMaskingAlgorithm javadoc), ready to save as a
#      file and upload via the engine's file-upload mechanism.
#   3. It also prints a keyed fingerprint (HMAC-SHA256 of a fixed label under the DEK) -- NOT the
#      key itself -- so an operator can confirm the engine's algorithm instance is using the same
#      key as this deployment without ever pasting/comparing the raw key value in two places.
#      cryptoProvider/cipherAlgorithm/maskingScheme aren't secret, so those are printed as-is;
#      just make sure the *same build* of DynamicMasking.jar is installed on the engine, since
#      FIRST-NAME-LOOKUP/LAST-NAME-LOOKUP index into a bundled resource file that must match too.
#
# Usage: ./scripts/sync-engine-config.sh [.env path, default ./.env]
set -euo pipefail

ENV_FILE="${1:-.env}"
if [[ ! -f "$ENV_FILE" ]]; then
    echo "No such file: $ENV_FILE" >&2
    exit 1
fi

# shellcheck disable=SC1090 -- intentionally sourcing a var-only .env file
set -a
source "$ENV_FILE"
set +a

: "${DATA_ENCRYPTION_KEY_BASE64:?DATA_ENCRYPTION_KEY_BASE64 must be set in $ENV_FILE (KMS-only .env files have no plaintext DEK to sync from -- generate one with scripts/generate-key.sh first)}"
CRYPTO_PROVIDER="${CRYPTO_PROVIDER:-BCFIPS}"
CIPHER_ALGORITHM="${CIPHER_ALGORITHM:-AES-CBC-CTS}"
MASKING_SCHEME="${MASKING_SCHEME:-}"

KEY_HEX=$(echo -n "$DATA_ENCRYPTION_KEY_BASE64" | base64 -d | xxd -p -c 256)
# awk '{print $NF}' (not $2): openssl's HMAC output format varies by platform/version -- some
# prefix "HMAC-SHA256(stdin)= " before the hex digest, some print the digest alone. $NF (last
# field) gets the digest either way; $2 would silently come back empty in the no-prefix case.
FINGERPRINT=$(echo -n "dynamicmasking-config-fingerprint" \
    | openssl dgst -sha256 -mac HMAC -macopt "hexkey:${KEY_HEX}" | awk '{print $NF}')

KEYFILE_JSON_PATH="${KEYFILE_JSON_PATH:-./engine-keyfile.json}"
cat > "$KEYFILE_JSON_PATH" <<EOF
{"dataEncryptionKeyBase64": "${DATA_ENCRYPTION_KEY_BASE64}"}
EOF
chmod 600 "$KEYFILE_JSON_PATH"

cat <<EOF
Wrote ${KEYFILE_JSON_PATH} -- upload this as the engine algorithm instance's "keyFile" reference
(masking engine UI: Manage Algorithms > your algorithm > keyFile > upload; or via the API's
FileUploadApi.uploadFile(), then reference the returned upload id as
"delphix-file://upload/<id>" in the algorithm's keyFile field).

Set these fields to match this deployment's .env exactly:
  cryptoProvider   = ${CRYPTO_PROVIDER}
  cipherAlgorithm  = ${CIPHER_ALGORITHM}
$( [[ -n "$MASKING_SCHEME" ]] && echo "  maskingScheme    = ${MASKING_SCHEME}  (OneWayMaskingAlgorithm instance, if used)" )

Config fingerprint (safe to paste into a ticket/chat -- NOT the key itself):
  ${FINGERPRINT}

To confirm the engine's algorithm instance uses the *same* key as this deployment: mask a known
probe value on the engine (e.g. via a test job or the algorithm's built-in self-test), mask the
same value here (e.g. \`curl -XPOST localhost:4051/v1/tokenize -d '{"values":["sync-check"]}'\`),
and diff the resulting tokens -- if the two engine/standalone deployments share a key, provider,
algorithm and jar build, matching inputs always produce matching outputs (see README.md's
"Keeping the Delphix engine in sync" section for why -- these algorithms are pure functions of
(value, key), so there's no runtime handshake, just this one-time/rotation-time distribution).
EOF
