#!/usr/bin/env bash
# Round-trips sample rows from the local Postgres stand-in through the plain REST API
# (tokenization-api, not the Redshift-specific Lambda endpoints -- see scripts/test-udf.sh for
# that) and verifies detokenize(tokenize(x)) == x. Requires `docker compose up -d` to already be
# running.
#
# Deliberately avoids `mapfile` (bash 4+) since macOS ships bash 3.2 by default.
set -euo pipefail

BASE_URL="http://localhost:4051"

wait_for() {
    for _ in $(seq 1 30); do
        if curl -sf -o /dev/null "$BASE_URL/healthz"; then
            return 0
        fi
        sleep 1
    done
    echo "Timed out waiting for $BASE_URL/healthz" >&2
    exit 1
}

# Builds {"values": ["v1", "v2", ...]} and POSTs it to the given path.
invoke() {
    local path=$1
    shift
    local values_json
    values_json=$(printf '%s\n' "$@" | jq -R . | jq -s .)
    local body
    body=$(jq -n --argjson values "$values_json" '{values: $values}')
    curl -sf -X POST "$BASE_URL$path" -H 'Content-Type: application/json' -d "$body"
}

echo "Waiting for tokenization-api..."
wait_for

echo "Reading sample rows from Postgres..."
NAMES=()
while IFS= read -r line; do
    [[ -n "$line" ]] && NAMES+=("$line")
done < <(docker compose exec -T postgres \
    psql -U inlinereidentify -d inlinereidentify -t -A -c "SELECT full_name FROM customers ORDER BY id;")

echo "Original values:"
printf '  %s\n' "${NAMES[@]}"

echo "Tokenizing (POST /v1/tokenize)..."
TOKENIZE_RESPONSE=$(invoke /v1/tokenize "${NAMES[@]}")
echo "$TOKENIZE_RESPONSE" | jq .
TOKENS=()
while IFS= read -r line; do
    [[ -n "$line" ]] && TOKENS+=("$line")
done < <(echo "$TOKENIZE_RESPONSE" | jq -r '.results[]')

echo "Tokens:"
printf '  %s\n' "${TOKENS[@]}"

echo "Reidentifying (POST /v1/reidentify)..."
REIDENTIFY_RESPONSE=$(invoke /v1/reidentify "${TOKENS[@]}")
echo "$REIDENTIFY_RESPONSE" | jq .
RECOVERED=()
while IFS= read -r line; do
    [[ -n "$line" ]] && RECOVERED+=("$line")
done < <(echo "$REIDENTIFY_RESPONSE" | jq -r '.results[]')

echo "Verifying round-trip..."
FAIL=0
for i in "${!NAMES[@]}"; do
    if [[ "${NAMES[$i]}" != "${RECOVERED[$i]}" ]]; then
        echo "MISMATCH at row $i: '${NAMES[$i]}' != '${RECOVERED[$i]}'" >&2
        FAIL=1
    fi
done

if [[ $FAIL -eq 0 ]]; then
    echo "PASS: all rows round-tripped correctly"
else
    echo "FAIL: round-trip mismatch"
    exit 1
fi
