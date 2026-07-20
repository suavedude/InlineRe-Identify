# Delphix DynamicMasking

A Delphix Continuous Compliance (masking) plugin with two reversible `MaskingAlgorithm<String>`
implementations: a from-scratch **fully homomorphic encryption (FHE)** scheme, and a more
conventional **deterministic tokenization** algorithm under a pluggable crypto provider/algorithm
(default AES, FIPS-validated). Masking a column encrypts/tokenizes the value; re-identifying it
recovers the original.

The tokenization core also runs standalone, outside the Delphix engine, as a [Redshift Lambda
UDF](#redshift-lambda-udf), as a [plain REST API](#other-databases-plain-rest-api) for every
other database, as a [Kafka masking bridge](#streaming-kafka) for message streams, and as a
[SQL Interception proxy](#sql-interception) that masks known-sensitive columns in arbitrary query
results transparently. The [browser demo UI](#browser-demo-ui) organizes these as **Environments**
(`Streaming`/`Tokenization`/`SQL Interception` purposes), modeled on the real Delphix Continuous
Compliance product's own Environments page.

## Why FHE specifically

NIST's Privacy-Enhancing Cryptography project tracks FHE as a technique for computing on
encrypted data without decrypting it first: https://csrc.nist.gov/Projects/pec/fhe. Most
FHE schemes NIST surveys there (BGV, BFV, CKKS, TFHE) are lattice-based and require large native
libraries (Microsoft SEAL, OpenFHE, HElib, Lattigo) with no mature pure-Java implementation.

This plugin instead implements the **DGHV scheme** ("Fully Homomorphic Encryption over the
Integers", van Dijk/Gentry/Halevi/Vaikuntanathan, EUROCRYPT 2010), which works directly with
`BigInteger` arithmetic and needs no native dependencies — making it practical to embed directly
in a masking-engine plugin jar. The homomorphic add/multiply operations described in the scheme
are exposed in `DghvCipher` for completeness/demonstration, even though the masking algorithm
itself only needs encrypt and decrypt.

## How it works

- `crypto/DghvCipher` — core scheme: `keyGen`, `encryptBit`, `decryptBit`,
  `homomorphicAdd` (XOR), `homomorphicMultiply` (AND).
- `crypto/FheSecurityProfile` — bit-size parameter sets (`COMPACT`, `HARDENED`).
- `crypto/DeterministicKeyStream` — turns a passphrase into a reproducible secret key, so the
  same key can be re-derived later for re-identification (possibly in a different process/job).
- `crypto/FheStringCodec` — encrypts/decrypts a whole `String` by encrypting every bit of its
  UTF-8 bytes individually and packing the resulting ciphertexts into a Base64 token.
- `FullyHomomorphicEncryptionAlgorithm` — the `MaskingAlgorithm<String>` plugin class. Calls
  `FheStringCodec.encrypt` in `MASK`/`TOKENIZE` mode and `FheStringCodec.decrypt` in
  `REIDENTIFY` mode.

### Configuration

| Field | Required | Description |
|---|---|---|
| `secretPassphrase` | yes | Used to deterministically derive the FHE secret key. Must be identical on the masking job and any job that re-identifies the data. |
| `securityProfile` | no (default `COMPACT`) | One of `COMPACT`, `HARDENED`. Must match between mask and reidentify. |

## Tokenization algorithm (pluggable provider + algorithm)

In addition to the FHE algorithm, the plugin includes a second, more conventional
`MaskingAlgorithm<String>`: deterministic tokenization under a **configurable crypto provider**
and **configurable cipher algorithm** -- neither is hardcoded, both are resolved by name at
runtime, and both can be extended with new implementations without touching this module's
source.

- `tokenization/spi` — the two extension points:
  - `CryptoProvider` / `CryptoProviderFactory` — a JCE `Security` provider (e.g. `BCFIPS`,
    `SunJCE`) plus idempotent registration logic.
  - `TokenizationScheme` / `TokenizationSchemeFactory` — a reversible tokenize/detokenize
    algorithm bound to a resolved `CryptoProvider`.
  - `CryptoProviderRegistry` / `TokenizationSchemeRegistry` — resolve a config string (e.g.
    `"BCFIPS"`, `"AES-CBC-CTS"`) to an implementation via `java.util.ServiceLoader`.
- Built-in providers: `BCFIPS` (Bouncy Castle FIPS, approved-only mode -- default) and `SunJCE`
  (the JDK's bundled provider, no extra dependency, no FIPS validation).
- Built-in algorithm: `AES-CBC-CTS` (default) — `tokenization/TokenCipher` handles inputs of at
  least one AES block (16 UTF-8 bytes) with ciphertext stealing (`CS3Padding`) and a fixed
  all-zero IV, so the token is the same length class as the input with no padding block;
  `tokenization/ShortValueCipher` is the fallback for shorter inputs (CTS is undefined below one
  block), same key/provider/IV but standard `PKCS5Padding`. `tokenization/TokenizationAlgorithm`
  picks between them by input length and prefixes the token with a one-character marker (`L`/`S`)
  so re-identification routes back to the matching cipher. Accepts any valid AES key length --
  16/24/32 bytes selects AES-128/192/256.

  **Provider portability note:** `CS3Padding` is Bouncy Castle-specific naming for the
  ciphertext-stealing mode; the long-value path is therefore only verified to work under BCFIPS.
  The short-value path (`PKCS5Padding`) is portable and round-trips under both built-in providers.
  A provider that can't perform a given transformation fails loudly (`NoSuchPaddingException`
  wrapped as `MaskingException`) rather than silently producing wrong output.

Because the IV is fixed, equal plaintexts always produce equal tokens (referential integrity),
at the cost of leaking value-equality/frequency across the token set — the same tradeoff
documented for the FHE algorithm's determinism.

### Configuration

| Field | Required | Description |
|---|---|---|
| `dataEncryptionKeyBase64` | yes | Base64-encoded key for the configured `cipherAlgorithm` (16, 24, or 32 bytes for the default `AES-CBC-CTS`). Must be identical on the masking job and any job that re-identifies the data. |
| `cryptoProvider` | no (default `BCFIPS`) | JCE provider id, resolved via `CryptoProviderRegistry`. Must match between mask and reidentify (see the portability note above). |
| `cipherAlgorithm` | no (default `AES-CBC-CTS`) | Tokenization scheme id, resolved via `TokenizationSchemeRegistry`. Must match between mask and reidentify. |

`validate()` round-trips a probe value through the resolved provider/algorithm/key at job start,
so a bad combination (unknown id, wrong key length, unsupported transformation) fails immediately
with a clear message instead of on the first masked row.

### Adding a new provider or algorithm

Both extension points are plain `ServiceLoader` SPIs — no core code changes needed:

1. Implement `CryptoProviderFactory` and/or `TokenizationSchemeFactory` (public no-arg
   constructor) in any jar on the classpath.
2. List the implementation's fully-qualified class name in
   `META-INF/services/com.delphix.dynamicmasking.tokenization.spi.CryptoProviderFactory` (or
   `...TokenizationSchemeFactory`) — see `src/main/resources/META-INF/services/` for the format
   the built-ins use.
3. Select it via `cryptoProvider` / `cipherAlgorithm` (Delphix plugin config) or
   `CRYPTO_PROVIDER` / `CIPHER_ALGORITHM` (Lambda env vars, see below).

## Building

```
./gradlew jar
```

Produces `build/libs/DynamicMasking.jar`, installable as a Delphix masking engine plugin.

```
./gradlew test
```

Runs the crypto and algorithm unit tests.

### Upgrading the masking-extensibility-api SDK

`build.gradle` compiles against two vendored jars in `libs/` (`masking-extensibility-api-*.jar`,
`semantic-version-*.jar`), versioned by `gradle.properties`' `maskingExtensibilityVer`/
`semanticVer` properties. To upgrade to a newer SDK release:

1. Download the new `masking-extensibility-api-<version>.jar` (+ `-javadoc.jar` if wanted) and
   `semantic-version-<version>.jar` from artifactory.
2. Place them in `libs/`, and remove the old version's jars from `libs/`.
3. Update `maskingExtensibilityVer` / `semanticVer` in `gradle.properties` to match.
4. Run `./gradlew clean build` — a breaking API change in the new version surfaces here
   immediately, as a compile failure against this plugin's code.

## Standalone tokenization service

The same pluggable `spi` tokenize/detokenize core used by `TokenizationAlgorithm` above (see
[`BatchTokenizer`](src/main/java/com/delphix/dynamicmasking/tokenization/BatchTokenizer.java)
for the shared batch/null/failure-handling logic) is also exposed outside the Delphix engine, as
two separate entry points that don't depend on each other:

- **Redshift Lambda UDF** ([`RedshiftUdfHandler`](src/main/java/com/delphix/dynamicmasking/tokenization/lambda/RedshiftUdfHandler.java))
  — for Redshift specifically, since `CREATE EXTERNAL FUNCTION ... LAMBDA` is how it calls out.
- **Plain REST API** ([`TokenizationHttpServer`](src/main/java/com/delphix/dynamicmasking/tokenization/http/TokenizationHttpServer.java))
  — for every other database or application that can make an outbound HTTP call: self-hosted
  Postgres, MySQL, Snowflake External Functions, BigQuery Remote Functions, or just app code.

Both parse their own wire format into a list of values and hand it to `BatchTokenizer`, so the
two can never disagree on null-handling or failure accounting, and provider/algorithm/key
configuration works identically across both (same env var names).

### Data encryption key: KMS envelope encryption

Both entry points resolve the key the same way,
[`DataEncryptionKeySource`](src/main/java/com/delphix/dynamicmasking/tokenization/key/DataEncryptionKeySource.java),
via the `KEY_SOURCE` environment variable:

| `KEY_SOURCE` | Env vars used | Use case |
|---|---|---|
| `KMS` (default) | `DATA_ENCRYPTION_KEY_CIPHERTEXT_BASE64`, optional `KMS_KEY_ID` | Real deployments. The DEK is stored encrypted under a KMS parent/customer master key; resolved once per process (Lambda cold start, or HTTP server startup) via `kms:Decrypt` and cached in memory (never logged/written to disk). |
| `PLAINTEXT` | `DATA_ENCRYPTION_KEY_BASE64` | Local/dev only (see docker-compose below) — raw Base64 DEK, no AWS calls. |

To deploy with KMS: create a CMK, wrap a DEK under it, and give the process's IAM role/role
`kms:Decrypt` on that key:

```
DEK_BASE64=$(openssl rand -base64 16)
aws kms encrypt --key-id alias/dynamicmasking-parent-key \
    --plaintext fileb://<(echo -n "$DEK_BASE64" | base64 -d) \
    --query CiphertextBlob --output text
# -> set as DATA_ENCRYPTION_KEY_CIPHERTEXT_BASE64
```

**How `kms:Decrypt` credentials get resolved** — `DataEncryptionKeySource` calls `KmsClient.create()`
with no explicit credential provider, so it's the AWS SDK's default chain, checked in this order:
env vars, `~/.aws` profile, then (on EC2, with nothing else set) the instance role via IMDS. In
practice that means three ways to grant access, from most to least common:

| Approach | Extra env vars | When to use |
|---|---|---|
| EC2 instance role | none | Normal case on EC2 (see `deploy/ec2/`) — no credentials to store or rotate, AWS handles it via IMDS. |
| `~/.aws` profile mount | none (see the `docker-compose.yml` volume mount) | Local dev on a machine that already has `aws configure`d credentials. |
| Static/temporary env vars | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, + `AWS_SESSION_TOKEN` if temporary/STS | No instance role available, or running somewhere without IMDS at all (on-prem, another cloud). `AWS_SESSION_TOKEN` only applies to temporary credentials (assumed-role, SSO) — omit it for a long-lived IAM user's static keys. |

The env-var approach needs no code changes — `docker-compose.yml` and
`deploy/ec2/tokenization-api.env.example` already pass all three through if set.

### Redshift Lambda UDF

Implements Redshift's [Lambda UDF](https://docs.aws.amazon.com/redshift/latest/dg/udf-creating-a-lambda-sql-udf.html)
request/response contract, letting you call `tokenize(value)` / `reidentify(token)` as a scalar
SQL function directly from Redshift.

The same jar is deployed as **two** separate Lambda functions (one per Redshift external
function), distinguished only by the `UDF_OPERATION` environment variable (`TOKENIZE` or
`REIDENTIFY`) — the request/response JSON shape is identical either way. Provider/algorithm are
env-var driven too, same ids as the Delphix plugin's `cryptoProvider`/`cipherAlgorithm` config:

| Env var | Default | |
|---|---|---|
| `CRYPTO_PROVIDER` | `BCFIPS` | resolved via `CryptoProviderRegistry` |
| `CIPHER_ALGORITHM` | `AES-CBC-CTS` | resolved via `TokenizationSchemeRegistry` |

```
./gradlew lambdaJar rawCryptoLibs
```

Produces `build/libs/DynamicMasking-lambda.jar` (handler + AWS SDK) and
`build/raw-crypto-libs/bc-fips-*.jar` (Bouncy Castle FIPS, kept as its own untouched jar file
rather than merged in — see the `rawCryptoLibs` comment in `build.gradle` for why). Both are
copied onto the Lambda's classpath by `Dockerfile.lambda`; a `CRYPTO_PROVIDER` that doesn't need
bc-fips (e.g. `SunJCE`) still works fine with that jar present but unused.

#### Redshift setup

```sql
CREATE OR REPLACE EXTERNAL FUNCTION tokenize(value VARCHAR)
RETURNS VARCHAR STABLE
LAMBDA 'dynamicmasking-tokenize'
IAM_ROLE 'arn:aws:iam::<account-id>:role/RedshiftLambdaUdfRole';

CREATE OR REPLACE EXTERNAL FUNCTION reidentify(token VARCHAR)
RETURNS VARCHAR STABLE
LAMBDA 'dynamicmasking-reidentify'
IAM_ROLE 'arn:aws:iam::<account-id>:role/RedshiftLambdaUdfRole';

SELECT tokenize(credit_card) FROM customers;
SELECT reidentify(credit_card_token) FROM customers_tokenized;
```

### Other databases: plain REST API

For anything that isn't Redshift, `TokenizationHttpServer` exposes the same core over plain
HTTP/JSON — no AWS Lambda dependency, no Redshift-specific contract:

```
POST /v1/tokenize            {"values": ["a", null, "b"]}  ->  {"results": ["tok-a", null, "tok-b"], "failureCount": 0}
POST /v1/reidentify           same shape, reverse direction
POST /v1/mask/full-name       same shape; one-way, non-reversible -- see below
POST /v1/mask/credit-card     same shape; keeps -/space separators in place
POST /v1/mask/email           same shape; keeps the domain, redacts the local part
GET  /healthz                 200 once provider/algorithm/key are resolved
```

A `null` in `values` passes through as `null` in `results` without counting as a failure; a
value that fails to tokenize/detokenize (bad token, wrong key, etc.) also comes back `null`, but
is counted in `failureCount` so the caller can tell the difference. Malformed request bodies get
a `400`; the server never returns partially-wrong data.

The three `/v1/mask/*` endpoints are always on -- unlike `cipherAlgorithm`, there's no env var
that changes what they do. Each is permanently fixed to one scheme
(`FULL-NAME-MASK`/`CREDIT-CARD-MASK`/`EMAIL-MASK`) on purpose: a single generic `mask()` whose
behavior depends on process config is easy to point at the wrong data (e.g. running an email
through a scheme meant for names), where one endpoint per data shape can't be misapplied that
way. They're one-way -- there's no reidentify counterpart.

Unlike the Lambda handler, **one process serves both directions** — `/v1/tokenize` and
`/v1/reidentify` are just different paths on the same server, not separate deployments. Same
`CRYPTO_PROVIDER` / `CIPHER_ALGORITHM` / `KEY_SOURCE` env vars as the Lambda handler, plus `PORT`
(default `4051`).

```
./gradlew httpServerJar rawCryptoLibs
```

Produces `build/libs/DynamicMasking-http-server.jar` (handler + Jackson + AWS SDK) —
`build/raw-crypto-libs/bc-fips-*.jar` is shared with the Lambda jar above.

#### Integration examples

**Self-hosted Postgres/Redshift-alike**, via the [`http`](https://github.com/pramsey/pgsql-http)
extension — this repo's docker-compose Postgres actually has it installed and wired up (see
`docker/postgres/Dockerfile` and `docker/postgres/udf.sql`, and the "Running locally" section
below):

```sql
CREATE EXTENSION IF NOT EXISTS http;

CREATE OR REPLACE FUNCTION tokenize(value text) RETURNS text AS $$
  SELECT (content::json ->> 'results')::json ->> 0
  FROM http_post('http://tokenization-api:4051/v1/tokenize',
                  json_build_object('values', ARRAY[value])::text, 'application/json');
$$ LANGUAGE sql;

SELECT tokenize(credit_card) FROM customers;
```

**Snowflake**, via an [External Function](https://docs.snowflake.com/en/sql-reference/external-functions-introduction)
pointed at this API through your cloud's API integration (API Gateway on AWS, equivalent on
Azure/GCP) — Snowflake's wrapper `{"data": [[0, value], ...]}` request needs a thin adapter in
front of `/v1/tokenize`, since it differs from this API's plain `{"values": [...]}`.

**BigQuery**, via a [Remote Function](https://cloud.google.com/bigquery/docs/remote-functions)
— same idea: BigQuery's `{"calls": [[value], ...]}` contract needs a thin adapter, typically a
small Cloud Function/Cloud Run proxy translating to/from this API.

**MySQL / application code**: no native HTTP-calling UDF mechanism in stock MySQL — call
`/v1/tokenize` from the application tier instead, batching rows the same way.

### Streaming (Kafka)

[`KafkaMaskingBridge`](src/main/java/com/delphix/dynamicmasking/tokenization/kafka/KafkaMaskingBridge.java)
consumes JSON messages from a Kafka input topic, tokenizes the configured sensitive fields via the
same `BatchTokenizer` core the REST API and Lambda UDF use, and produces an envelope
(`{"original": ..., "tokenized": ..., "failureCount": ..., "errors": ...}`) to an output topic.
Plain `kafka-clients`, not Kafka Streams — this is one stateless consume/tokenize/produce loop, no
joins/windowing/state needed.

```
POST /v1/kafka/produce   body is the raw JSON test message -> produced onto KAFKA_INPUT_TOPIC
GET  /v1/kafka/messages  -> JSON array of recently tokenized envelopes, newest first
GET  /healthz
```

Env vars: `KAFKA_BOOTSTRAP_SERVERS`, `KAFKA_INPUT_TOPIC` (default `dynamicmasking.demo.input`),
`KAFKA_OUTPUT_TOPIC` (default `dynamicmasking.demo.output`), `SENSITIVE_FIELDS` (default
`full_name,email,credit_card`), plus the same `CRYPTO_PROVIDER`/`CIPHER_ALGORITHM`/`KEY_SOURCE`
(+DEK) vars every other tokenization entry point reads.

```
./gradlew kafkaJar rawCryptoLibs
```

Produces `build/libs/DynamicMasking-kafka.jar`. In the demo UI, this is what a `Streaming`-purpose
Environment's detail view drives — see [Browser demo UI](#browser-demo-ui) below.

### SQL Interception

[`SqlInterceptionHttpServer`](src/main/java/com/delphix/dynamicmasking/tokenization/sqlproxy/SqlInterceptionHttpServer.java)
runs an arbitrary read-only `SELECT` against the sample Postgres and masks known-sensitive columns
in the result **transparently** — unlike `docker/postgres/udf.sql`'s SQL functions above, the
query never has to call `tokenize()`/`mask_*()` itself.

Column matching is by result-set column label (case-insensitive), against a fixed sensitive-column
set (`full_name`, `email`, `credit_card`) — there is deliberately no SQL parser. An aliased
sensitive column (`SELECT email AS contact`) isn't recognized and passes through unmasked; that's
an accepted demo-scope tradeoff, not a bug.

```
POST /v1/query   {"sql": "SELECT ..."}  ->  {"columns": [...], "rows": [[...]], "maskedColumns": [...]}
GET  /healthz
```

Only plain `SELECT` statements are accepted (no stacked statements, no write keywords) — this is a
best-effort filter for a local single-user demo, **not a security boundary**. Env vars: `DB_HOST`,
`DB_PORT` (default `5432`), `DB_NAME`, `DB_USER`, `DB_PASSWORD` for the fixed JDBC target, plus
`KEY_SOURCE` (+ DEK vars) — no `CRYPTO_PROVIDER`/`CIPHER_ALGORITHM` needed since one-way masking
schemes don't take one.

```
./gradlew sqlproxyJar rawCryptoLibs
```

Produces `build/libs/DynamicMasking-sqlproxy.jar`. In the demo UI, this is what a
`SQL Interception`-purpose Environment's detail view drives.

### Running locally with Docker + Postgres

`docker-compose.yml` runs against a local Postgres (`postgres`, seeded with sample rows from
`docker/postgres/init.sql`):

| Service | Entry point | Port |
|---|---|---|
| `tokenize-udf` / `reidentify-udf` | Redshift Lambda UDF, under AWS's local Runtime Interface Emulator (RIE) — the same image/code path used in real AWS | `9001` / `9002` |
| `tokenization-api` | Plain REST API | `4051` |
| `sql-interception-proxy` | SQL Interception (transparent masking over `postgres`) | `4053` |
| `kafka` | Single-node Kafka broker (KRaft mode) | `9092` |
| `kafka-masking-bridge` | Streaming (Kafka) masking bridge | `4052` |

```
./gradlew lambdaJar httpServerJar sqlproxyJar kafkaJar rawCryptoLibs
cp .env.example .env && ./scripts/generate-key.sh >> .env   # KEY_SOURCE=PLAINTEXT for local dev
docker compose up -d --build
./scripts/test-udf.sh        # Redshift Lambda UDF round-trip
./scripts/test-http-api.sh   # plain REST API round-trip
```

Or invoke either directly:

```
curl -XPOST 'http://localhost:9001/2015-03-31/functions/function/invocations' \
    -d '{"request_id":"t1","num_records":1,"arguments":[["4111-1111-1111-1111"]]}'

curl -XPOST http://localhost:4051/v1/tokenize \
    -H 'Content-Type: application/json' -d '{"values":["4111-1111-1111-1111"]}'
```

**Note:** `CREATE EXTERNAL FUNCTION ... LAMBDA` is Redshift-only, so `tokenize-udf`/`reidentify-udf`
can't be called from this local Postgres's SQL layer — `scripts/test-udf.sh` calls that endpoint
directly over HTTP instead, the same way Redshift's Lambda UDF machinery would.

The plain REST API path is different: this stack's `postgres` service is a custom image
(`docker/postgres/Dockerfile`) with the `pgsql-http` extension installed, and
`docker/postgres/udf.sql` defines `tokenize(text)` / `reidentify(text)` SQL functions on top of it
that call `tokenization-api` directly — the SQL-level demo the note above used to ask about now
actually works:

```sql
SELECT full_name, tokenize(full_name) AS token, reidentify(tokenize(full_name)) AS recovered
FROM customers;
```

One HTTP round trip per row/call — fine for interactive use, but batch through `/v1/tokenize`
directly (as `scripts/test-http-api.sh` does) for bulk work.

## Keeping a Delphix engine in sync (referential integrity)

`TokenizationAlgorithm` and the fixed-scheme one-way algorithms (`FullNameMaskingAlgorithm`,
`CreditCardMaskingAlgorithm`, `EmailMaskingAlgorithm` — see `FixedSchemeMaskingAlgorithm`) inside
a Delphix Continuous Compliance engine job, and the standalone AWS deployment (Lambda UDF, HTTP
server), run the *same* code (`TokenizationSchemeRegistry`/`OneWayMaskingSchemeRegistry`) against
a key supplied separately to each. Both are pure functions of `(value, key)` — there's no runtime
handshake between the engine and the standalone deployment, and none is needed. Referential
integrity (a value masked by one side and reidentified/compared against the other matches) holds
*if and only if* both sides are configured identically:

1. **The same DEK, byte-for-byte.** Never generate the key independently on each side — treat
   the plaintext DEK as a single secret with exactly one source of truth (a vault, AWS Secrets
   Manager, etc.), distributed to both consumers rather than regenerated per consumer:
   - The engine only accepts the key inline (`dataEncryptionKeyBase64`) or via an uploaded
     `keyFile` — it has no KMS-decrypt path of its own.
   - The standalone deployment can additionally take a KMS-wrapped copy (`KEY_SOURCE=KMS`) of
     that same plaintext DEK, so the plaintext only ever needs to exist in the vault and briefly
     at engine-config time, never baked into the standalone deployment's own config.
2. **The same `cryptoProvider`/`cipherAlgorithm`** for `TokenizationAlgorithm` specifically —
   these aren't secret, just need to match. A mismatched provider or algorithm id won't round-trip
   even with the right key; `AES-GCM` won't match *at all* between the two sides (or even between
   two calls on the same side) since it's deliberately non-deterministic — don't use it where
   cross-system referential integrity matters. The one-way masking algorithms have no such field
   to mismatch: each engine algorithm class and each standalone endpoint/SQL function is
   permanently fixed to one scheme (`FullNameMaskingAlgorithm`/`mask_fullname()` always run
   `FULL-NAME-MASK`, and so on), so there's nothing to keep in sync beyond the key itself.
3. **The same jar build.** `FULL-NAME-MASK` indexes into `first-names.txt`/`last-names.txt`
   bundled in the jar; if the engine and the standalone deployment ever run different builds
   where those resources changed, the same input maps to a different name on each side even with
   a matching key.

**Distribution/rotation workflow:** `./scripts/sync-engine-config.sh` reads the plaintext DEK out
of `.env` and writes `engine-keyfile.json` — the exact `{"dataEncryptionKeyBase64": "..."}` shape
the engine's `keyFile` config field expects (upload it via the engine UI, or automate the upload
with the SDK's `com.delphix.masking.api.FileUploadApi.uploadFile()` + reference the returned
upload id as `delphix-file://upload/<id>`, then `AlgorithmApi.getAlgorithm(id)` /
`updateAlgorithm(id, algorithm)` to point the algorithm instance's `keyFile` at it — both classes
ship in `sdkTools/lib/masking-api-client-*.jar`). The script also prints a keyed fingerprint
(HMAC-SHA256 of a fixed label under the DEK — never the key itself) so two operators can confirm
they're both looking at the same key without pasting the raw value into a ticket/chat. Whenever
the DEK is rotated, re-run it and push the new `keyFile` to the engine in the same change as the
standalone deployment's new KMS ciphertext — the two must move together, not independently,
which is also why re-masking historical data under a rotated key needs a planned
reidentify-then-re-mask migration rather than an in-place swap.

**Validation safety net (already built in, not a substitute for the above):** both algorithms'
`validate()`/`setup()` round-trip a probe value through the configured key/scheme at job start,
so a *wrong-shaped* key or an unresolvable scheme id fails loudly on the engine side immediately.
It can't catch "right shape, wrong value" (e.g. a stale or independently-rotated key that happens
to still be a valid length) — only the single-source-of-truth distribution above guarantees that.

## Deploying the REST API to EC2

`deploy/ec2/` runs `tokenization-api` as a real network service on a single EC2 instance: Docker
+ a systemd unit, built from source on the instance at boot via user-data. This is for the
standalone REST API only — the Lambda UDF deploys straight to AWS Lambda (see above), and doesn't
belong on EC2.

1. **Wrap a DEK under a real KMS CMK** the same way the [KMS envelope encryption](#data-encryption-key-kms-envelope-encryption)
   section above describes, and note the resulting `DATA_ENCRYPTION_KEY_CIPHERTEXT_BASE64`.
2. **Create an IAM role** for the instance with `kms:Decrypt` on that CMK (nothing else needed —
   `KmsClient.create()` resolves credentials from the instance role automatically, no key/secret
   ever touches the instance).
3. **Launch an EC2 instance** (Amazon Linux 2023; anything with a couple GB of RAM building a
   small Java project is plenty):
   - Attach the IAM role from step 2.
   - Security group: allow inbound TCP on the chosen `PORT` (default `4051`) only from wherever
     your database/application tier actually calls from — not `0.0.0.0/0`.
   - In a subnet with outbound internet access (to clone the repo and install packages).
   - Paste `deploy/ec2/user-data.sh` as the instance's **user data**, after filling in its
     `CONFIGURE` block (`GIT_REPO_URL` — this checkout has no remote configured yet, push it
     somewhere reachable first — plus the ciphertext DEK from step 1 and any non-default
     `KMS_KEY_ID`/`AWS_REGION`/`CRYPTO_PROVIDER`/`CIPHER_ALGORITHM`).
4. **Boot it.** Cloud-init installs Docker/git/a JDK, clones the repo, runs
   `./gradlew httpServerJar rawCryptoLibs`, builds the `Dockerfile.http-server` image locally,
   writes `/etc/dynamicmasking/tokenization-api.env`, and installs+starts
   `deploy/ec2/tokenization-api.service` (`Restart=always`, survives reboots).
5. **Verify:**
   ```bash
   curl http://<instance-ip>:4051/healthz
   ```
   Logs: `journalctl -u tokenization-api -f` (systemd/cloud-init) or `docker logs tokenization-api`.

**Updating after first boot:** user-data only runs once. To pick up new commits or an env-file
edit, SSH in and run `dynamicmasking-rebuild [git-ref]` — installed by user-data at
`/usr/local/bin/`, it re-pulls, rebuilds the image, and restarts the service.

**Why `--network host` in the systemd unit:** bridged Docker containers on EC2 need an extra IMDS
hop-limit bump (`HttpPutResponseHopLimit ≥ 2` at instance launch) to reach the instance metadata
service that the IAM-role KMS credentials come from. Host networking sidesteps that entirely — the
container reaches IMDS the same way any host process would — at the cost of the container sharing
the instance's network namespace directly, which is fine for a single-service instance but worth
knowing if you later co-locate other services on the same box.

This intentionally doesn't provision the instance/role/security-group itself (no Terraform/CFN
here) — bring your own IaC or click through the console; `deploy/ec2/user-data.sh` is the part that
turns a running instance into a working service.

## Browser demo UI

`demo/` is a small UI over this repo's standalone entry points — `demo/index.html` (static,
vanilla JS) served by `demo/server.py`, a [FastAPI](https://fastapi.tiangolo.com/) app (see
`demo/requirements.txt` — `pip install -r demo/requirements.txt` once before first running it).

The home page is an **Environments** list, modeled on the real Delphix Continuous Compliance
product's own Environments page: each Environment belongs to an **Application** and has a
**Purpose** — `Tokenization` (the tokenize/reidentify panel plus the opt-in "SQL Functions" panel
over `docker/postgres/udf.sql`), `Streaming` (the [Kafka masking bridge](#streaming-kafka)), or
`SQL Interception` (the [transparent-masking proxy](#sql-interception)). Use "+ Application" and
"+ Environment" to create one, then open it to reach the Purpose-specific Jobs/Rule Sets/
Connectors tabs — Connectors is a real, persisted list (demo metadata only; it doesn't change what
a Job actually connects to, which is always the real docker-compose service). A global
**Settings** page (separate from any Environment) holds ["Sync Key from Engine"](#sync-key-from-a-live-delphix-engine).
Environments/Applications/Connectors are demo metadata stored locally in `demo/environments.json`
(gitignored) — since every Environment of a given Purpose talks to the same single backend
service in this stack, they're an organizational label, not a separate configuration.

**API docs:** open `http://localhost:4041/docs` for interactive Swagger UI — it documents the
*real* REST contracts of `tokenization-api`, `sql-interception-proxy`, and
`kafka-masking-bridge` (proxied through this same process at matching `/v1/*` paths), not the
browser UI's own internal `/api/*` plumbing.

**Always run it on the same machine as the `tokenization-api` you want to exercise** — your Mac
against the local `docker-compose` stack, or directly on an EC2 instance against its own
systemd-managed container:

```bash
pip install -r demo/requirements.txt   # once
python3 demo/server.py
# open http://localhost:4041 (UI) or http://localhost:4041/docs (Swagger)
```

With no configuration at all, it targets `http://localhost:4051` — i.e. *this machine's own*
`tokenization-api`, whichever machine that happens to be. That's the normal way to run it; there's
nothing machine-specific to set.

For the deliberate exception — testing a browser on one machine against a `tokenization-api`
running on another (e.g. checking an EC2 deployment from your Mac without SSHing in) — override
the target with `TOKENIZATION_API_BASE`:

```bash
TOKENIZATION_API_BASE=http://<remote-host>:4051 python3 demo/server.py
```

The tokenize/reidentify panel works identically either way. The crypto-configuration panel
("Apply Configuration") only makes sense for the same-machine case — it works by running
`docker compose` on the machine `demo/server.py` itself is running on, which has no effect on a
remote target — so it's automatically disabled (with an explanatory note) whenever
`TOKENIZATION_API_BASE` is overridden to a non-`localhost`/`127.0.0.1` address. To reconfigure a
remote deployment, use that deployment's own tooling instead (e.g. `deploy/ec2/rebuild.sh` on the
target instance).

`DEMO_PORT` (default `4041`) controls the port the UI itself listens on, independent of
`TOKENIZATION_API_BASE`. The Streaming and SQL Interception panels talk to `kafka-masking-bridge`/
`sql-interception-proxy` via `KAFKA_BRIDGE_BASE` (default `http://localhost:4052`) and
`SQL_PROXY_BASE` (default `http://localhost:4053`), same override pattern as
`TOKENIZATION_API_BASE`.

### Sync Key from a live Delphix Engine

The **Settings** page's "Sync Key from Engine" pulls a Delphix Masking Engine's configured data
encryption key into this deployment's `.env` — given the engine's host/IP, username, and password
(never persisted — used in-memory for the one request), `demo/server.py` logs into the engine's
REST API, finds an algorithm with a resolvable key file, and writes the key locally the same way
manually pasting one into "Apply Configuration" does, then rebuilds `tokenization-api`. This is
the reverse direction of [`scripts/sync-engine-config.sh`](#keeping-a-delphix-engine-in-sync-referential-integrity)
above, which pushes a local key *to* the engine instead of pulling one *from* it.

**This talks to a real product's REST API and its exact contract varies by engine version** — the
login step (`POST {host}/masking/api/login`) follows Delphix's documented session convention, but
the algorithm-listing/key-download endpoints in `demo/server.py`'s `_engine_find_key()` are a
best-effort implementation, not verified against a live engine. If it fails against your engine,
check `ENGINE_API_BASE_PATH` and those endpoint paths against your engine version's API docs
first, rather than assuming the rest of the feature (the UI, the local `.env`/rebuild plumbing) is
broken. Only works against the local docker-compose stack, for the same reason "Apply
Configuration" does.

**Running it persistently on an EC2 deployment** (rather than one-off from your own machine):
`deploy/ec2/demo-ui.service` runs `demo/server.py` the same way `tokenization-api.service` and
`postgres.service` run their pieces — `Restart=always`, survives reboots. It's opt-in, not part
of a default EC2 deployment (see `DEPLOY_DEMO_UI` in `deploy/ec2/user-data.sh`, defaults `false`),
since it's an always-on web UI you may not want exposed on every instance. To add it to an
already-running instance:

```bash
sudo install -m 0644 deploy/ec2/demo-ui.service /etc/systemd/system/demo-ui.service
sudo systemctl daemon-reload
sudo systemctl enable --now demo-ui
```

Then open `http://<instance-ip>:4041` — remember to allow inbound `4041` in the security group.
No `TOKENIZATION_API_BASE` is set in the unit, so (per the "no configuration at all" default
above) it automatically targets that same instance's own `tokenization-api`.
`dynamicmasking-rebuild` restarts it too, if installed, when you redeploy.

## Important caveats

- **Not all corrupted tokens are detectable as corrupted.** `/v1/reidentify` (and the Lambda/SQL
  equivalents) surface a clear error for a malformed token where possible -- bad Base64, an
  unrecognized mode marker, a decrypt that fails padding validation (see `BatchTokenizer`'s
  `errors` field). But `AES-CBC-CTS`/`ShortValueCipher` have no MAC/authentication tag (see the
  crypto-contract note in `TokenCipher.java`), so some corrupted ciphertext decrypts "successfully"
  into different (wrong) plaintext instead of throwing -- there's no cryptographic way to
  distinguish that from a legitimately different value without adding authenticated encryption,
  which would change the token format for everyone. Don't treat the absence of an error as proof a
  reidentified value is correct if the token's provenance is untrusted.
- **Ciphertext blow-up.** Bit-wise integer FHE is not space-efficient: every plaintext *bit*
  becomes a ciphertext of roughly `gammaBits/8` bytes. With the `COMPACT` profile
  (`gammaBits=2048`), a single character (8 bits) costs ~2 KB; with `HARDENED`
  (`gammaBits=12288`) it costs ~12 KB. Only use this on short fields.
- **No bootstrapping.** This implementation omits FHE bootstrapping, so the homomorphic
  add/multiply operations only stay correct for a small number of chained operations before noise
  overwhelms the ciphertext. The masking algorithm itself doesn't need this (it only encrypts and
  later decrypts, with no operations in between), but don't build deep homomorphic circuits on
  top of `DghvCipher` without addressing this.
- **Not independently security-reviewed.** `FheSecurityProfile`'s bit sizes are a usability/size
  compromise, not a vetted security parameterization from the DGHV literature (real parameter
  sets are far larger and proportionally more expensive). The deterministic key derivation
  (`DeterministicKeyStream`) is a simplified HMAC-counter construction, not a standards-compliant
  DRBG. For protecting real sensitive data, prefer a vetted, audited library and standard
  symmetric/format-preserving encryption unless you specifically need the homomorphic-computation
  property of FHE.
