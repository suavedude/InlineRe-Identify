# InlineRe-Identify — Masking Plugin

A Delphix Continuous Compliance (masking) plugin with two reversible `MaskingAlgorithm<String>`
implementations: a from-scratch **fully homomorphic encryption (FHE)** scheme, and a more
conventional **deterministic tokenization** algorithm under a pluggable crypto provider/algorithm
(default AES, FIPS-validated). Masking a column encrypts/tokenizes the value; re-identifying it
recovers the original.

The tokenization core also runs standalone, outside the Delphix engine, as a [Redshift Lambda
UDF](#redshift-lambda-udf) and as a [plain REST API](#other-databases-plain-rest-api) for every
other database.

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
   `META-INF/services/com.inlinereidentify.masking.tokenization.spi.CryptoProviderFactory` (or
   `...TokenizationSchemeFactory`) — see `src/main/resources/META-INF/services/` for the format
   the built-ins use.
3. Select it via `cryptoProvider` / `cipherAlgorithm` (Delphix plugin config) or
   `CRYPTO_PROVIDER` / `CIPHER_ALGORITHM` (Lambda env vars, see below).

## Building

```
./gradlew jar
```

Produces `build/libs/inlineFhe.jar`, installable as a Delphix masking engine plugin.

```
./gradlew test
```

Runs the crypto and algorithm unit tests.

## Standalone tokenization service

The same pluggable `spi` tokenize/detokenize core used by `TokenizationAlgorithm` above (see
[`BatchTokenizer`](src/main/java/com/inlinereidentify/masking/tokenization/BatchTokenizer.java)
for the shared batch/null/failure-handling logic) is also exposed outside the Delphix engine, as
two separate entry points that don't depend on each other:

- **Redshift Lambda UDF** ([`RedshiftUdfHandler`](src/main/java/com/inlinereidentify/masking/tokenization/lambda/RedshiftUdfHandler.java))
  — for Redshift specifically, since `CREATE EXTERNAL FUNCTION ... LAMBDA` is how it calls out.
- **Plain REST API** ([`TokenizationHttpServer`](src/main/java/com/inlinereidentify/masking/tokenization/http/TokenizationHttpServer.java))
  — for every other database or application that can make an outbound HTTP call: self-hosted
  Postgres, MySQL, Snowflake External Functions, BigQuery Remote Functions, or just app code.

Both parse their own wire format into a list of values and hand it to `BatchTokenizer`, so the
two can never disagree on null-handling or failure accounting, and provider/algorithm/key
configuration works identically across both (same env var names).

### Data encryption key: KMS envelope encryption

Both entry points resolve the key the same way,
[`DataEncryptionKeySource`](src/main/java/com/inlinereidentify/masking/tokenization/key/DataEncryptionKeySource.java),
via the `KEY_SOURCE` environment variable:

| `KEY_SOURCE` | Env vars used | Use case |
|---|---|---|
| `KMS` (default) | `DATA_ENCRYPTION_KEY_CIPHERTEXT_BASE64`, optional `KMS_KEY_ID` | Real deployments. The DEK is stored encrypted under a KMS parent/customer master key; resolved once per process (Lambda cold start, or HTTP server startup) via `kms:Decrypt` and cached in memory (never logged/written to disk). |
| `PLAINTEXT` | `DATA_ENCRYPTION_KEY_BASE64` | Local/dev only (see docker-compose below) — raw Base64 DEK, no AWS calls. |

To deploy with KMS: create a CMK, wrap a DEK under it, and give the process's IAM role/role
`kms:Decrypt` on that key:

```
DEK_BASE64=$(openssl rand -base64 16)
aws kms encrypt --key-id alias/inline-reidentify-parent-key \
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

Produces `build/libs/inlineReIdentify-lambda.jar` (handler + AWS SDK) and
`build/raw-crypto-libs/bc-fips-*.jar` (Bouncy Castle FIPS, kept as its own untouched jar file
rather than merged in — see the `rawCryptoLibs` comment in `build.gradle` for why). Both are
copied onto the Lambda's classpath by `Dockerfile.lambda`; a `CRYPTO_PROVIDER` that doesn't need
bc-fips (e.g. `SunJCE`) still works fine with that jar present but unused.

#### Redshift setup

```sql
CREATE OR REPLACE EXTERNAL FUNCTION tokenize(value VARCHAR)
RETURNS VARCHAR STABLE
LAMBDA 'inline-reidentify-tokenize'
IAM_ROLE 'arn:aws:iam::<account-id>:role/RedshiftLambdaUdfRole';

CREATE OR REPLACE EXTERNAL FUNCTION reidentify(token VARCHAR)
RETURNS VARCHAR STABLE
LAMBDA 'inline-reidentify-reidentify'
IAM_ROLE 'arn:aws:iam::<account-id>:role/RedshiftLambdaUdfRole';

SELECT tokenize(credit_card) FROM customers;
SELECT reidentify(credit_card_token) FROM customers_tokenized;
```

### Other databases: plain REST API

For anything that isn't Redshift, `TokenizationHttpServer` exposes the same core over plain
HTTP/JSON — no AWS Lambda dependency, no Redshift-specific contract:

```
POST /v1/tokenize     {"values": ["a", null, "b"]}  ->  {"results": ["tok-a", null, "tok-b"], "failureCount": 0}
POST /v1/reidentify    same shape, reverse direction
GET  /healthz          200 once provider/algorithm/key are resolved
```

A `null` in `values` passes through as `null` in `results` without counting as a failure; a
value that fails to tokenize/detokenize (bad token, wrong key, etc.) also comes back `null`, but
is counted in `failureCount` so the caller can tell the difference. Malformed request bodies get
a `400`; the server never returns partially-wrong data.

Unlike the Lambda handler, **one process serves both directions** — `/v1/tokenize` and
`/v1/reidentify` are just different paths on the same server, not separate deployments. Same
`CRYPTO_PROVIDER` / `CIPHER_ALGORITHM` / `KEY_SOURCE` env vars as the Lambda handler, plus `PORT`
(default `4051`).

```
./gradlew httpServerJar rawCryptoLibs
```

Produces `build/libs/inlineReIdentify-http-server.jar` (handler + Jackson + AWS SDK) —
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

### Running locally with Docker + Postgres

`docker-compose.yml` runs three services against a local Postgres (`postgres`, seeded with
sample rows from `docker/postgres/init.sql`):

| Service | Entry point | Port |
|---|---|---|
| `tokenize-udf` / `reidentify-udf` | Redshift Lambda UDF, under AWS's local Runtime Interface Emulator (RIE) — the same image/code path used in real AWS | `9001` / `9002` |
| `tokenization-api` | Plain REST API | `4051` |

```
./gradlew lambdaJar httpServerJar rawCryptoLibs
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
   writes `/etc/inline-reidentify/tokenization-api.env`, and installs+starts
   `deploy/ec2/tokenization-api.service` (`Restart=always`, survives reboots).
5. **Verify:**
   ```bash
   curl http://<instance-ip>:4051/healthz
   ```
   Logs: `journalctl -u tokenization-api -f` (systemd/cloud-init) or `docker logs tokenization-api`.

**Updating after first boot:** user-data only runs once. To pick up new commits or an env-file
edit, SSH in and run `inline-reidentify-rebuild [git-ref]` — installed by user-data at
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

`demo/` is a small crypto-config-and-tokenize/reidentify UI over `tokenization-api`'s REST
endpoints — `demo/index.html` (static, vanilla JS) served by `demo/server.py` (stdlib-only
Python, no dependencies to install).

**Always run it on the same machine as the `tokenization-api` you want to exercise** — your Mac
against the local `docker-compose` stack, or directly on an EC2 instance against its own
systemd-managed container:

```bash
python3 demo/server.py
# open http://localhost:4041
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
`TOKENIZATION_API_BASE`.

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
`inline-reidentify-rebuild` restarts it too, if installed, when you redeploy.

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
