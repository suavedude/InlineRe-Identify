#!/usr/bin/env bash
# Round-trips sample rows from the local Postgres stand-in through the tokenize-udf and
# reidentify-udf containers using the exact JSON shape Redshift sends to a Lambda UDF, and
# verifies detokenize(tokenize(x)) == x. Requires `docker compose up -d` to already be running.
#
# Deliberately avoids `mapfile` (bash 4+) since macOS ships bash 3.2 by default.
set -euo pipefail


TOKENIZE_URL="http://localhost:9001/2015-03-31/functions/function/invocations"
REIDENTIFY_URL="http://localhost:9002/2015-03-31/functions/function/invocations"

wait_for() {
    local url=$1
    for _ in $(seq 1 30); do
        if curl -sf -o /dev/null -X POST "$url" -d '{"request_id":"warmup","num_records":1,"arguments":[["warmup"]]}'; then
            return 0
        fi
        sleep 1
    done
    echo "Timed out waiting for $url" >&2
    exit 1
}

# Builds a Redshift Lambda UDF request body: {"arguments": [["v1"], ["v2"], ...], ...} and
# invokes the given RIE endpoint with it.
invoke() {
    local url=$1
    shift
    local args_json
    args_json=$(printf '%s\n' "$@" | jq -R . | jq -s 'map([.])')
    local body
    body=$(jq -n --argjson args "$args_json" \
        '{request_id: "local-test", cluster: "local", user: "local", database: "inlinereidentify",
          external_function: "local", query_id: 1, num_records: ($args | length), arguments: $args}')
    curl -sf -X POST "$url" -d "$body"
}

echo "Waiting for Lambda RIE endpoints..."
wait_for "$TOKENIZE_URL"
wait_for "$REIDENTIFY_URL"

echo "Reading sample rows from Postgres..."
NAMES=()
while IFS= read -r line; do
    [[ -n "$line" ]] && NAMES+=("$line")
done < <(docker compose exec -T postgres \
    psql -U inlinereidentify -d inlinereidentify -t -A -c "SELECT full_name FROM customers ORDER BY id;")

echo "Original values:"
printf '  %s\n' "${NAMES[@]}"

echo "Tokenizing..."
TOKENIZE_RESPONSE=$(invoke "$TOKENIZE_URL" "${NAMES[@]}")
echo "$TOKENIZE_RESPONSE" | jq .
TOKENS=()
while IFS= read -r line; do
    [[ -n "$line" ]] && TOKENS+=("$line")
done < <(echo "$TOKENIZE_RESPONSE" | jq -r '.results[]')

echo "Tokens:"
printf '  %s\n' "${TOKENS[@]}"

echo "Reidentifying..."
REIDENTIFY_RESPONSE=$(invoke "$REIDENTIFY_URL" "${TOKENS[@]}")
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
