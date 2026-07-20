#!/usr/bin/env python3
"""
Local demo backend for the DynamicMasking tokenization API, built on FastAPI (requires
`pip install -r demo/requirements.txt` -- see README.md's "Browser demo UI" section).

Serves demo/index.html plus two kinds of endpoints:

- The browser UI's own backend-for-frontend routes, under /api/* (hidden from the Swagger docs
  at /docs -- see `include_in_schema=False` throughout -- since they're demo-UI plumbing, not a
  documented public contract): /api/status, /api/configure, /api/tokenize, /api/reidentify,
  /api/db/connect, /api/db/query, /api/sql/query, /api/engine/sync, /api/applications,
  /api/environments (incl. DELETE, cascade-deletes the environment's connectors), /api/connectors,
  /api/connectors/{id}/ruleset (connector-scoped Rule Sets tab -- a typed Ruleset object, KAFKA
  connectors get {type: "topic", topic, messageType, size, fields: [...]} sourced live from
  kafka-ui-proxy, CRYPTO/DATABASE connectors get {type: "table", table, columns: [...]} sourced
  live from Postgres information_schema (see get_connector_ruleset/_kafka_ruleset/_table_ruleset)
  -- only the per-field/column algorithm assignment is actually persisted, everything else is
  recomputed fresh every call so it can't go stale; algorithm suggestions from
  SUGGESTED_ALGORITHM_BY_FIELD), /api/algorithms (this SDK's registered scheme ids, for the
  Rule Sets tab's dropdown), /api/connectors/{id}/messages (per-connector Live Messages detail
  view -- raw messages from the connector's topic paired with a live masked preview computed from
  its saved Rule Set), /api/connectors/{id}/workflows + /api/workflows(/{id}/activate) (named "run
  configurations" tied to one connector -- see the Workflows section's module comment above
  list_workflows() for the active/inactive exclusivity rule), /api/kafka/produce,
  /api/kafka/messages.
- Typed proxy routes under /v1/* that mirror the *real* request/response contracts of the three
  standalone Java services this repo builds (TokenizationHttpServer, SqlInterceptionHttpServer,
  KafkaMaskingBridge) -- these are what /docs documents, per the Swagger/API-docs request: open
  http://localhost:4041/docs for interactive Swagger UI generated from the Pydantic models below.

Requires the docker-compose stack's images to have been built at least once already (see
README.md's "Running locally with Docker + Postgres" section) -- this script only
reconfigures/rebuilds the tokenization-api service, it doesn't run `./gradlew` itself.

/api/db/query executes whatever SQL the "SQL Functions" panel sends, as the credentials supplied
to /api/db/connect -- this is deliberate (the panel's whole point is letting you run ad hoc SQL,
including the tokenize()/mask_fullname()/mask_creditcard()/mask_email() calls it demos), not an
oversight. Fine for its intended use -- a single local user driving their own demo -- but this
server binds 0.0.0.0, so don't leave it reachable on a shared/untrusted network while connected
to a real database.

By default targets the local docker-compose stack (http://localhost:4051). Override with
TOKENIZATION_API_BASE to point at a remote deployment (e.g. the EC2 setup in deploy/ec2/) for
the tokenize/reidentify panel -- in that case /api/configure is disabled, since it works by
running `docker compose` on this machine, which has no effect on a remote target.
"""
import base64
import csv
import hashlib
import hmac
import io
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import Body, FastAPI
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = REPO_ROOT / ".env"
DEMO_DIR = Path(__file__).resolve().parent
TOKENIZATION_API_BASE = os.environ.get("TOKENIZATION_API_BASE", "http://localhost:4051")
IS_LOCAL_TARGET = "localhost" in TOKENIZATION_API_BASE or "127.0.0.1" in TOKENIZATION_API_BASE
SQL_PROXY_BASE = os.environ.get("SQL_PROXY_BASE", "http://localhost:4053")
KAFKA_BRIDGE_BASE = os.environ.get("KAFKA_BRIDGE_BASE", "http://localhost:4052")
DEMO_PORT = int(os.environ.get("DEMO_PORT", "4041"))
ENV_STORE_FILE = DEMO_DIR / "environments.json"

MANAGED_KEYS = (
    "KEY_SOURCE",
    "CRYPTO_PROVIDER",
    "CIPHER_ALGORITHM",
    "DATA_ENCRYPTION_KEY_BASE64",
    "DATA_ENCRYPTION_KEY_CIPHERTEXT_BASE64",
    "KMS_KEY_ID",
    "AWS_REGION",
    # Alternative to an EC2 instance role / mounted ~/.aws profile -- see README.md's "Data
    # encryption key: KMS envelope encryption" section. Not echoed back by /api/status (see
    # status construction below), same as the DEK fields -- write-only from the UI's perspective.
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
)


def read_env():
    env = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip()
    return env


def write_env(updates):
    existing = read_env()
    existing.update(updates)
    lines = [f"{key}={existing.get(key, '')}" for key in MANAGED_KEYS]
    ENV_FILE.write_text("\n".join(lines) + "\n")


def apply_configuration(payload):
    if not IS_LOCAL_TARGET:
        raise ValueError(
            f"TOKENIZATION_API_BASE is set to {TOKENIZATION_API_BASE}, not a local address -- "
            "Apply Configuration only works against the local docker-compose stack (it runs "
            "`docker compose` on this machine). To reconfigure a remote deployment, use "
            "deploy/ec2/rebuild.sh (or equivalent) on the target instance instead."
        )

    key_source = (payload.get("keySource") or "PLAINTEXT").upper()
    if key_source not in ("PLAINTEXT", "KMS"):
        raise ValueError("keySource must be PLAINTEXT or KMS")

    updates = {
        "KEY_SOURCE": key_source,
        "CRYPTO_PROVIDER": payload.get("cryptoProvider") or "BCFIPS",
        "CIPHER_ALGORITHM": payload.get("cipherAlgorithm") or "AES-CBC-CTS",
        "DATA_ENCRYPTION_KEY_BASE64": "",
        "DATA_ENCRYPTION_KEY_CIPHERTEXT_BASE64": "",
        "KMS_KEY_ID": "",
        "AWS_REGION": "",
        "AWS_ACCESS_KEY_ID": "",
        "AWS_SECRET_ACCESS_KEY": "",
        "AWS_SESSION_TOKEN": "",
    }

    if key_source == "PLAINTEXT":
        dek = payload.get("dataEncryptionKeyBase64", "").strip()
        if not dek:
            raise ValueError("dataEncryptionKeyBase64 is required for KEY_SOURCE=PLAINTEXT")
        updates["DATA_ENCRYPTION_KEY_BASE64"] = dek
    else:
        ciphertext = payload.get("dataEncryptionKeyCiphertextBase64", "").strip()
        if not ciphertext:
            raise ValueError("dataEncryptionKeyCiphertextBase64 is required for KEY_SOURCE=KMS")
        updates["DATA_ENCRYPTION_KEY_CIPHERTEXT_BASE64"] = ciphertext
        updates["KMS_KEY_ID"] = payload.get("kmsKeyId", "").strip()
        updates["AWS_REGION"] = payload.get("awsRegion", "").strip()
        # All optional -- normally left blank so the SDK falls through to an instance role or
        # the mounted ~/.aws profile instead. AWS_SESSION_TOKEN only makes sense alongside the
        # other two (temporary/STS credentials), but there's no harm writing it alone.
        updates["AWS_ACCESS_KEY_ID"] = payload.get("awsAccessKeyId", "").strip()
        updates["AWS_SECRET_ACCESS_KEY"] = payload.get("awsSecretAccessKey", "").strip()
        updates["AWS_SESSION_TOKEN"] = payload.get("awsSessionToken", "").strip()

    write_env(updates)
    rebuild_tokenization_api()


def rebuild_tokenization_api():
    """Rebuilds/restarts the tokenization-api container so it picks up the .env changes apply_configuration
    just wrote, then polls /healthz until it's back up."""
    subprocess.run(
        ["docker", "compose", "up", "-d", "--build", "tokenization-api"],
        cwd=REPO_ROOT, check=True, capture_output=True, text=True, timeout=300,
    )

    deadline = time.time() + 30
    last_error = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{TOKENIZATION_API_BASE}/healthz", timeout=2) as resp:
                if resp.status == 200:
                    return
        except Exception as e:  # noqa: BLE001 -- retry loop, any failure just means "not up yet"
            last_error = e
        time.sleep(1)

    logs = subprocess.run(
        ["docker", "compose", "logs", "--no-color", "--tail", "50", "tokenization-api"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    ).stdout
    raise RuntimeError(f"tokenization-api did not become healthy ({last_error}).\n\n{logs}")


# In-memory only (never written to .env/disk) -- credentials entered in the "SQL Functions" panel
# for /api/db/query to reuse. Single global since this is a single-user local demo, same
# simplifying assumption the rest of this script already makes.
DB_CONN = {}


def _run_psql(conn, args, timeout):
    """Runs psql inside the already-running postgres container (it's bundled there already --
    see docker/postgres/Dockerfile -- so this needs no new host dependency) against `conn`."""
    cmd = [
        "docker", "compose", "exec", "-T",
        "-e", f"PGPASSWORD={conn['password']}",
        "postgres", "psql",
        "-h", conn["host"], "-p", str(conn["port"]),
        "-U", conn["user"], "-d", conn["database"],
        *args,
    ]
    return subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, timeout=timeout)


def db_connect(payload):
    conn = {
        "host": (payload.get("host") or "localhost").strip(),
        "port": str(payload.get("port") or "5432").strip(),
        "database": (payload.get("database") or "dynamicmasking").strip(),
        "user": (payload.get("user") or "dynamicmasking").strip(),
        "password": payload.get("password") or "",
    }
    result = _run_psql(conn, ["-c", "SELECT 1;"], timeout=10)
    if result.returncode != 0:
        raise ValueError(result.stderr.strip() or "connection failed")
    DB_CONN.clear()
    DB_CONN.update(conn)


def db_query(sql):
    if not DB_CONN:
        raise ValueError("Not connected -- use 'Connect' above first.")
    if not sql or not sql.strip():
        raise ValueError("SQL is required")
    # --csv gives a header row plus CSV data rows with no footer, easy to parse without a driver.
    result = _run_psql(DB_CONN, ["--csv", "-c", sql], timeout=15)
    if result.returncode != 0:
        raise ValueError(result.stderr.strip() or "query failed")
    rows = list(csv.reader(io.StringIO(result.stdout)))
    if not rows:
        return {"columns": [], "rows": []}
    return {"columns": rows[0], "rows": rows[1:]}


# Falls back to the same defaults the Database Credentials card is pre-filled with -- so the
# Tokenization/SQL Interception Rule Set tab works without requiring an explicit "Connect" click
# first, same as the Kafka Rule Set tab needing no setup step to sample a topic.
DEFAULT_DB_CONN = {
    "host": "localhost", "port": "5432", "database": "dynamicmasking",
    "user": "dynamicmasking", "password": "dynamicmasking",
}


def _fetch_table_columns(table_name):
    """Live schema introspection (information_schema.columns) for the Tokenization/SQL
    Interception Rule Set tab -- real Postgres column names/types/sizes, the table/column
    equivalent of _fetch_messages()'s live Kafka sampling. Returns [] (not an error) if the table
    doesn't exist or postgres isn't reachable, same fail-quiet convention _fetch_messages() uses
    for a topic with no messages yet."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", table_name or ""):
        return []  # not a plausible identifier -- don't even attempt the query
    conn = DB_CONN or DEFAULT_DB_CONN
    sql = (
        "SELECT column_name, data_type, COALESCE(character_maximum_length, numeric_precision) "
        f"FROM information_schema.columns WHERE table_name = '{table_name}' "
        "ORDER BY ordinal_position;"
    )
    try:
        result = _run_psql(conn, ["--csv", "-c", sql], timeout=10)
    except Exception:  # noqa: BLE001 -- postgres container not up yet, docker not available, etc.
        return []
    if result.returncode != 0:
        return []
    rows = list(csv.reader(io.StringIO(result.stdout)))
    if len(rows) <= 1:
        return []
    return [
        {"name": r[0], "dataType": r[1], "size": int(r[2]) if len(r) > 2 and r[2] else None}
        for r in rows[1:]
    ]


def _forward_json(base_url, path, payload, timeout=15):
    """POSTs `payload` (a dict) as JSON to base_url+path and returns (status, parsed body) --
    the shared plumbing every /api/* and /v1/* proxy route below is built on."""
    req = urllib.request.Request(
        base_url + path, data=json.dumps(payload).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read())


def sql_proxy_query(payload):
    """Forwards straight to sql-interception-proxy's /v1/query -- unlike db_query() above (which
    shells out to psql because there's no Java process fronting arbitrary raw SQL), the masking
    logic here lives in that Java process, so this is a plain proxy, same shape as /api/tokenize."""
    return _forward_json(SQL_PROXY_BASE, "/v1/query", payload)


def kafka_produce(payload):
    """Forwards straight to kafka-masking-bridge's /v1/kafka/produce -- browser JS can't speak
    the Kafka wire protocol, so this HTTP proxy is how the Streaming panel reaches it."""
    return _forward_json(KAFKA_BRIDGE_BASE, "/v1/kafka/produce", payload)


def kafka_messages():
    """Forwards straight to kafka-masking-bridge's /v1/kafka/messages (recently tokenized envelopes)."""
    with urllib.request.urlopen(KAFKA_BRIDGE_BASE + "/v1/kafka/messages", timeout=15) as resp:
        return resp.status, json.loads(resp.read())


# --- Environments / Applications store (Environments list + Add Environment modal) --------
# Local JSON-file-backed store -- this metadata (which Application an Environment belongs to,
# its Purpose) has no natural home in the sample Postgres, and is single-user/local-demo scoped
# like everything else in this script. Not written concurrently in practice (single local user
# clicking through the UI), so no locking needed.
def _read_store():
    if not ENV_STORE_FILE.exists():
        return {"applications": [], "environments": [], "connectors": [], "workflows": []}
    store = json.loads(ENV_STORE_FILE.read_text())
    store.setdefault("connectors", [])  # tolerate a store written before connectors existed
    store.setdefault("workflows", [])  # tolerate a store written before workflows existed
    # Tolerate connectors written before topicName/bootstrapServers/streamType/tableName/ruleset existed.
    for connector in store["connectors"]:
        connector.setdefault("topicName", None)
        connector.setdefault("bootstrapServers", None)
        connector.setdefault("streamType", None)
        connector.setdefault("tableName", None)
        connector.setdefault("ruleset", {})
    return store


def _write_store(store):
    ENV_STORE_FILE.write_text(json.dumps(store, indent=2) + "\n")


def list_applications():
    return _read_store()["applications"]


def add_application(payload):
    name = (payload.get("name") or "").strip()
    if not name:
        raise ValueError("name is required")
    store = _read_store()
    if name not in store["applications"]:
        store["applications"].append(name)
        _write_store(store)
    return {"name": name}


VALID_PURPOSES = ("Streaming", "Tokenization", "SQL Interception")


def list_environments():
    return _read_store()["environments"]


def add_environment(payload):
    application = (payload.get("application") or "").strip()
    name = (payload.get("name") or "").strip()
    purpose = (payload.get("purpose") or "").strip()
    if not application or not name or not purpose:
        raise ValueError("application, name, and purpose are all required")
    if purpose not in VALID_PURPOSES:
        raise ValueError(f"purpose must be one of {', '.join(VALID_PURPOSES)}")

    store = _read_store()
    if application not in store["applications"]:
        store["applications"].append(application)
    next_id = max([e["id"] for e in store["environments"]], default=0) + 1
    environment = {
        "id": next_id,
        "application": application,
        "name": name,
        "purpose": purpose,
        "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    store["environments"].append(environment)
    _write_store(store)
    return environment


def delete_environment(environment_id):
    store = _read_store()
    environment = next((e for e in store["environments"] if str(e["id"]) == str(environment_id)), None)
    if environment is None:
        raise ValueError(f"No environment with id {environment_id}")
    removed_connector_ids = {
        str(c["id"]) for c in store["connectors"] if str(c["environmentId"]) == str(environment_id)
    }
    store["environments"] = [e for e in store["environments"] if str(e["id"]) != str(environment_id)]
    store["connectors"] = [c for c in store["connectors"] if str(c["environmentId"]) != str(environment_id)]
    store["workflows"] = [w for w in store["workflows"] if str(w["connectorId"]) not in removed_connector_ids]
    _write_store(store)
    return {"deleted": environment_id}


# Purpose -> the fixed connector category its environments' Connectors table groups under. Not
# user-chosen (unlike the real product's DATABASE/FILE/MAINFRAME) -- a Kafka broker or crypto
# config doesn't fit those, so each Purpose gets one category that actually describes it.
CONNECTOR_CATEGORY_BY_PURPOSE = {
    "Streaming": "KAFKA",
    "Tokenization": "CRYPTO",
    "SQL Interception": "DATABASE",
}


def list_connectors(environment_id):
    return [c for c in _read_store()["connectors"] if str(c["environmentId"]) == str(environment_id)]


def add_connector(payload):
    environment_id = payload.get("environmentId")
    name = (payload.get("name") or "").strip()
    connector_type = (payload.get("type") or "").strip()
    # Only set by the Streaming Add Connector modal's extra fields -- null for
    # Tokenization/SQL Interception connectors, which have no topic/broker of their own.
    topic_name = (payload.get("topicName") or "").strip() or None
    bootstrap_servers = (payload.get("bootstrapServers") or "").strip() or None
    stream_type = (payload.get("streamType") or "").strip() or None
    # Only set by the Tokenization/SQL Interception Add Connector modal's extra field -- null for
    # Streaming connectors, which have a topic instead of a table.
    table_name = (payload.get("tableName") or "").strip() or None
    if environment_id is None or not name or not connector_type:
        raise ValueError("environmentId, name, and type are all required")
    if stream_type and stream_type != "kafka":
        # Kinesis/Pub-Sub are shown disabled in the UI -- this is a defensive backstop, not the
        # primary guard.
        raise ValueError(f"Unsupported streamType '{stream_type}' -- only 'kafka' is available today")

    store = _read_store()
    environment = next((e for e in store["environments"] if str(e["id"]) == str(environment_id)), None)
    if environment is None:
        raise ValueError(f"No environment with id {environment_id}")

    next_id = max([c["id"] for c in store["connectors"]], default=0) + 1
    connector = {
        "id": next_id,
        "environmentId": environment["id"],
        "category": CONNECTOR_CATEGORY_BY_PURPOSE[environment["purpose"]],
        "name": name,
        "type": connector_type,
        "topicName": topic_name,
        "bootstrapServers": bootstrap_servers,
        "streamType": stream_type,
        "tableName": table_name,
        "ruleset": {},
        "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    store["connectors"].append(connector)
    _write_store(store)
    return connector


def _find_connector(store, connector_id):
    connector = next((c for c in store["connectors"] if str(c["id"]) == str(connector_id)), None)
    if connector is None:
        raise ValueError(f"No connector with id {connector_id}")
    return connector


def get_connector(connector_id):
    return _find_connector(_read_store(), connector_id)


# --- Algorithm registry + connector-scoped Ruleset (Streaming Rule Sets tab) ---------------
# Mirrors the SPI factories' actual id() values (src/main/java/com/delphix/dynamicmasking/
# onewaymasking/*SchemeFactory.java, tokenization/*SchemeFactory.java) -- a hardcoded, centralized
# copy for the same reason demo/index.html's ALGORITHM_MAPPING already was one: the browser/this
# script have no way to query the JVM's registries directly.
ALGORITHM_REGISTRY = [
    {"framework": "One-Way Masking", "algorithm_name": name} for name in (
        "FULL-NAME-MASK", "FIRST-NAME-LOOKUP", "LAST-NAME-LOOKUP", "EMAIL-MASK",
        "CREDIT-CARD-MASK", "DATE-SHIFT", "DATE-REDACT", "SEGMENT-MAPPING",
        "NUMBER-REDACT", "STRING-REDACT",
    )
] + [
    {"framework": "Tokenization", "algorithm_name": name} for name in (
        "AES-CBC-CTS", "AES-GCM", "AES-ECB",
    )
]

# Best-effort field-name -> suggested algorithm id, for fields this demo actually knows about
# (its own full_name/email/credit_card, plus EDI270's field names). Anything else gets no
# suggestion ("-- none --" in the UI) rather than a guess.
SUGGESTED_ALGORITHM_BY_FIELD = {
    "full_name": "FULL-NAME-MASK",
    "first_name": "FIRST-NAME-LOOKUP",
    "last_name": "LAST-NAME-LOOKUP",
    "email": "EMAIL-MASK",
    "email_address": "EMAIL-MASK",
    "credit_card": "CREDIT-CARD-MASK",
    "dob": "DATE-SHIFT",
    "date_of_birth": "DATE-SHIFT",
    "zip_code": "SEGMENT-MAPPING",
    # No dedicated SSN scheme in this SDK -- reversible tokenization is the closest safe default.
    "national_identifier": "AES-CBC-CTS",
}

KAFKA_UI_PROXY_BASE = os.environ.get("KAFKA_UI_PROXY_BASE", "http://localhost:8081")

# One-way algorithm id -> its /v1/mask/* path segment on tokenization-api (mirrors MASK_ENDPOINTS
# in TokenizationHttpServer.java) -- DATE-REDACT/NUMBER-REDACT/STRING-REDACT have no HTTP endpoint
# and are deliberately absent here, see _apply_mask_batch().
ALGORITHM_TO_MASK_PATH = {
    "FULL-NAME-MASK": "full-name",
    "CREDIT-CARD-MASK": "credit-card",
    "EMAIL-MASK": "email",
    "FIRST-NAME-LOOKUP": "first-name",
    "LAST-NAME-LOOKUP": "last-name",
    "DATE-SHIFT": "date-shift",
    "SEGMENT-MAPPING": "segment-mapping",
}
TOKENIZATION_ALGORITHMS = {"AES-CBC-CTS", "AES-GCM", "AES-ECB"}


def list_algorithms():
    return ALGORITHM_REGISTRY


def _apply_mask_batch(algorithm, values):
    """Masks a batch of values (all messages' value for one field) via the real tokenization-api,
    for the per-connector Live Messages view's masked-preview column. Returns a same-length list,
    all None if `algorithm` isn't live-invokable (see ALGORITHM_TO_MASK_PATH's comment) or the call
    fails -- never raises, so one bad/unsupported field can't break the whole table."""
    try:
        if algorithm in ALGORITHM_TO_MASK_PATH:
            _, body = _forward_json(
                TOKENIZATION_API_BASE, f"/v1/mask/{ALGORITHM_TO_MASK_PATH[algorithm]}", {"values": values})
        elif algorithm in TOKENIZATION_ALGORITHMS:
            _, body = _forward_json(TOKENIZATION_API_BASE, "/v1/tokenize", {"values": values})
        else:
            return [None] * len(values)
        return body["results"]
    except Exception:  # noqa: BLE001 -- tokenization-api down/unreachable, bad value, etc.
        return [None] * len(values)


def _fetch_messages(topic, limit=1):
    """Fetches up to `limit` recent messages from `topic` via kafka-ui-proxy's REST API (a
    server-sent-events stream of PHASE/CONSUMING/MESSAGE lines), newest first, returning their
    parsed JSON content -- or an empty list if the topic has no messages yet (or doesn't exist)."""
    url = f"{KAFKA_UI_PROXY_BASE}/api/clusters/local/topics/{urllib.parse.quote(topic, safe='')}/messages?limit={limit}"
    messages = []
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            for raw_line in resp:
                line = raw_line.decode("utf-8").strip()
                if not line.startswith("data:"):
                    continue
                event = json.loads(line[len("data:"):])
                if event.get("type") == "MESSAGE":
                    messages.append(json.loads(event["message"]["content"]))
    except Exception:  # noqa: BLE001 -- topic not found / kafka-ui-proxy not up yet / etc.
        return []
    messages.reverse()  # kafka-ui-proxy streams oldest-of-the-window first; we want newest first
    return messages


def _fetch_sample_message(topic):
    """One recent message from `topic`, or None if it has no messages yet -- see get_connector_ruleset()."""
    messages = _fetch_messages(topic, limit=1)
    return messages[0] if messages else None


def get_connector_live_messages(connector_id, limit=50):
    """Backs the per-connector Live Messages detail view for any connector whose topic isn't
    kafka-masking-bridge's own output topic (which /api/kafka/messages already serves, pre-joined
    into original/tokenized envelopes) -- e.g. EDI270, a raw source topic with no masking job.
    Pairs each raw message with a masked preview computed live from the connector's saved Rule Set
    (see get_connector_ruleset/save_connector_ruleset), one batched call per ruleset-assigned field
    rather than one call per field per message."""
    store = _read_store()
    connector = _find_connector(store, connector_id)
    topic = connector.get("topicName") or "dynamicmasking.demo.output"
    ruleset = connector.get("ruleset") or {}
    raw_messages = _fetch_messages(topic, limit=limit)

    masked_by_field = {}
    for field, algorithm in ruleset.items():
        values = [str(m[field]) if m.get(field) is not None else None for m in raw_messages]
        masked_by_field[field] = _apply_mask_batch(algorithm, values)

    messages = [
        {"raw": raw, "masked": {field: masked_by_field[field][i] for field in masked_by_field}}
        for i, raw in enumerate(raw_messages)
    ]
    return {"topic": topic, "messages": messages}


def _kafka_ruleset(connector):
    """Ruleset object for a KAFKA connector: live topic details (message format + a sampled
    message's byte size, both computed fresh every call, never persisted -- see the module
    docstring's Ruleset section) plus the per-field algorithm assignment, which IS persisted
    (connector["ruleset"])."""
    # Falls back to this demo's own output topic for connectors created before topicName existed.
    topic = connector.get("topicName") or "dynamicmasking.demo.output"
    sample = _fetch_sample_message(topic)
    saved_ruleset = connector.get("ruleset") or {}

    if sample is None:
        return {"type": "topic", "topic": topic, "fields": [],
                "note": f"No messages found on topic '{topic}' yet."}

    # kafka-masking-bridge's own output topic wraps the actual fields inside "original"/
    # "tokenized" (see KafkaMaskingBridge.tokenizeMessage) -- unwrap so the Ruleset table shows
    # the real field names (full_name/email/credit_card) rather than the envelope's own keys.
    if isinstance(sample, dict) and "original" in sample and "tokenized" in sample:
        sample = sample["original"]

    fields = []
    for key, value in sample.items():
        fields.append({
            "json_key": key,
            "sample_value": value,
            "algorithm": saved_ruleset.get(key),
            "suggested_algorithm": SUGGESTED_ALGORITHM_BY_FIELD.get(key),
        })
    return {
        "type": "topic",
        "topic": topic,
        # Every topic in this stack is JSON-encoded (producers + kafka-masking-bridge both only
        # ever write JSON) -- not a guess, just not worth a live check given it's always true here.
        "messageType": "JSON",
        "size": len(json.dumps(sample).encode("utf-8")),
        "fields": fields,
    }


def _table_ruleset(connector):
    """Ruleset object for a CRYPTO/DATABASE connector: live table/column details (real Postgres
    types/sizes via information_schema, computed fresh every call, never persisted) plus the
    per-column algorithm assignment, which IS persisted (connector["ruleset"]) -- the table/column
    equivalent of _kafka_ruleset()'s topic/field shape."""
    table = connector.get("tableName") or "customers"
    columns = _fetch_table_columns(table)
    saved_ruleset = connector.get("ruleset") or {}

    if not columns:
        return {"type": "table", "table": table, "columns": [],
                "note": f"No columns found for table '{table}' (is postgres running?)."}

    return {
        "type": "table",
        "table": table,
        "columns": [
            {
                "name": col["name"],
                "dataType": col["dataType"],
                "size": col["size"],
                "algorithm": saved_ruleset.get(col["name"]),
                "suggested_algorithm": SUGGESTED_ALGORITHM_BY_FIELD.get(col["name"]),
            }
            for col in columns
        ],
    }


def get_connector_ruleset(connector_id):
    store = _read_store()
    connector = _find_connector(store, connector_id)
    if connector["category"] == "KAFKA":
        return _kafka_ruleset(connector)
    return _table_ruleset(connector)


def save_connector_ruleset(connector_id, fields):
    store = _read_store()
    connector = _find_connector(store, connector_id)
    connector["ruleset"] = {key: value for key, value in fields.items() if value}
    _write_store(store)
    return connector["ruleset"]


# --- Workflows (Rule Sets tab) --------------------------------------------------------------
# A connector already has exactly one Ruleset (connector["ruleset"], above). A Workflow is a named
# "run configuration" against that (connector, ruleset) pair -- many can exist, but at most one is
# ever `active` per connector (enforced in activate_workflow()). NOTE: `active` is bookkeeping --
# which workflow *would* run -- not a live process being started/stopped; this demo has no
# generalized masking-workflow execution engine, same as the Jobs tab's other panels.
def list_workflows(connector_id):
    return [w for w in _read_store()["workflows"] if str(w["connectorId"]) == str(connector_id)]


def add_workflow(payload):
    connector_id = payload.get("connectorId")
    name = (payload.get("name") or "").strip()
    if connector_id is None or not name:
        raise ValueError("connectorId and name are required")
    store = _read_store()
    _find_connector(store, connector_id)  # raises if the connector doesn't exist
    next_id = max([w["id"] for w in store["workflows"]], default=0) + 1
    workflow = {
        "id": next_id,
        "connectorId": connector_id,
        "name": name,
        # First workflow created for a connector starts active by default -- otherwise a freshly
        # created connector would have a ruleset but no active workflow at all, which is a less
        # useful default than "the one workflow you just made."
        "active": not any(str(w["connectorId"]) == str(connector_id) for w in store["workflows"]),
        "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    store["workflows"].append(workflow)
    _write_store(store)
    return workflow


def _find_workflow(store, workflow_id):
    workflow = next((w for w in store["workflows"] if str(w["id"]) == str(workflow_id)), None)
    if workflow is None:
        raise ValueError(f"No workflow with id {workflow_id}")
    return workflow


def activate_workflow(workflow_id):
    store = _read_store()
    workflow = _find_workflow(store, workflow_id)
    for w in store["workflows"]:
        w["active"] = (str(w["id"]) == str(workflow_id)) if str(w["connectorId"]) == str(workflow["connectorId"]) else w["active"]
    _write_store(store)
    return list_workflows(workflow["connectorId"])


def delete_workflow(workflow_id):
    store = _read_store()
    _find_workflow(store, workflow_id)  # raises if not found
    store["workflows"] = [w for w in store["workflows"] if str(w["id"]) != str(workflow_id)]
    _write_store(store)
    return {"deleted": workflow_id}


# --- Delphix Masking Engine key sync (Settings tab) ---------------------------------------
# NOTE: this talks to a live Delphix Masking Engine's REST API. The login step (POST {base}/login
# with {"username", "password"} -> a session token in the response body's "Api-Session" field,
# sent back as the "Api-Session" header on subsequent calls) follows Delphix's documented masking
# API convention, but the algorithm-listing/key-download endpoints and response shapes below are
# a best-effort implementation that has NOT been verified against a live engine -- if this fails
# against your engine, check ENGINE_API_BASE_PATH and the endpoint paths in _engine_find_key()
# below against your specific engine version's API documentation first, rather than assuming the
# rest of this feature (the Settings tab UI, the local .env/rebuild plumbing) is broken too.
ENGINE_API_BASE_PATH = os.environ.get("ENGINE_API_BASE_PATH", "/masking/api")


def _engine_request(host, method, path, session=None, body=None):
    url = f"https://{host}{ENGINE_API_BASE_PATH}{path}"
    headers = {"Content-Type": "application/json"}
    if session:
        headers["Api-Session"] = session
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise ValueError(
            f"Engine request {method} {path} failed (HTTP {e.code}): "
            f"{e.read().decode('utf-8', 'replace')}"
        )


def _engine_login(host, username, password):
    resp = _engine_request(host, "POST", "/login", body={"username": username, "password": password})
    session = resp.get("Api-Session") or resp.get("apiSession")
    if not session:
        raise ValueError("Engine login did not return a session token (unexpected response shape)")
    return session


def _engine_find_key(host, session):
    """Best-effort: lists algorithms and returns the first one with a resolvable key file. See
    the module-level NOTE above -- confirm this against your engine's actual API before relying
    on it."""
    algorithms = _engine_request(host, "GET", "/algorithms", session=session)
    items = algorithms.get("responseList", algorithms) if isinstance(algorithms, dict) else algorithms
    for algo in items or []:
        key_ref = algo.get("keyFile") or algo.get("keyFileReference")
        if not key_ref:
            continue
        key_file = _engine_request(host, "GET", f"/file-downloads/{key_ref}", session=session)
        dek = key_file.get("dataEncryptionKeyBase64")
        if dek:
            return dek
    raise ValueError(
        "No algorithm with a resolvable key file was found on the engine -- this engine's "
        "algorithm/key-file API shape may differ from what _engine_find_key() expects; check "
        "demo/server.py's Delphix Masking Engine key sync section against your engine's actual "
        "API docs."
    )


def _config_fingerprint(dek_base64):
    """Matches scripts/sync-engine-config.sh's HMAC-SHA256-of-a-fixed-label scheme, so a
    fingerprint from either tool can be compared to confirm the engine and this deployment share
    a key, without ever comparing the raw key value."""
    key_bytes = base64.b64decode(dek_base64)
    return hmac.new(key_bytes, b"dynamicmasking-config-fingerprint", hashlib.sha256).hexdigest()


def engine_sync(payload):
    if not IS_LOCAL_TARGET:
        raise ValueError(
            f"TOKENIZATION_API_BASE is set to {TOKENIZATION_API_BASE}, not a local address -- "
            "Sync Key from Engine only works against the local docker-compose stack (it runs "
            "`docker compose` on this machine, same as Apply Configuration)."
        )

    host = (payload.get("host") or "").strip()
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    if not host or not username or not password:
        raise ValueError("host, username, and password are all required")

    session = _engine_login(host, username, password)
    dek_base64 = _engine_find_key(host, session)

    write_env({
        "KEY_SOURCE": "PLAINTEXT",
        "DATA_ENCRYPTION_KEY_BASE64": dek_base64,
        "DATA_ENCRYPTION_KEY_CIPHERTEXT_BASE64": "",
        "KMS_KEY_ID": "",
        "AWS_REGION": "",
        "AWS_ACCESS_KEY_ID": "",
        "AWS_SECRET_ACCESS_KEY": "",
        "AWS_SESSION_TOKEN": "",
    })
    rebuild_tokenization_api()
    return {"fingerprint": _config_fingerprint(dek_base64)}


# ============================================================================================
# Pydantic models for the /v1/* documented routes -- these mirror the *real* request/response
# shapes of TokenizationHttpServer, SqlInterceptionHttpServer, and KafkaMaskingBridge exactly
# (see their javadoc), so Swagger UI at /docs documents the actual Java service contracts.
# ============================================================================================

class BatchRequest(BaseModel):
    values: List[Optional[str]]


class BatchResponse(BaseModel):
    results: List[Optional[str]]
    failureCount: int
    errors: List[Optional[str]]


class SqlQueryRequest(BaseModel):
    sql: str


class SqlQueryResponse(BaseModel):
    columns: List[str]
    rows: List[List[Optional[str]]]
    maskedColumns: List[str]


class KafkaProduceAck(BaseModel):
    success: bool


class KafkaEnvelope(BaseModel):
    original: Dict[str, Any]
    tokenized: Dict[str, Any]
    failureCount: int
    errors: Dict[str, str]


class HealthStatus(BaseModel):
    status: str


app = FastAPI(
    title="DynamicMasking",
    description=(
        "Delphix DynamicMasking demo backend. The routes below (tagged by backing service) "
        "mirror the real REST contracts of the three standalone Java entry points this repo "
        "builds -- TokenizationHttpServer, SqlInterceptionHttpServer, and KafkaMaskingBridge -- "
        "proxied through this process so they're reachable/documented from one place. The "
        "browser demo UI's own /api/* backend-for-frontend routes are intentionally not listed "
        "here (see demo/server.py's module docstring)."
    ),
    version="1.0.0",
)


# --- Demo UI backend-for-frontend routes (/api/*) -- hidden from /docs ----------------------

@app.get("/", include_in_schema=False)
@app.get("/index.html", include_in_schema=False)
def index():
    return FileResponse(DEMO_DIR / "index.html", media_type="text/html; charset=utf-8")


@app.get("/api/status", include_in_schema=False)
def api_status():
    env = read_env()
    status = {
        "tokenizationApiBase": TOKENIZATION_API_BASE,
        "isLocalTarget": IS_LOCAL_TARGET,
        # These reflect this machine's .env, which only describes reality when the target is
        # local -- against a remote deployment they're not meaningful (the remote instance's own
        # env file is the source of truth there instead).
        "cryptoProvider": env.get("CRYPTO_PROVIDER", "BCFIPS"),
        "cipherAlgorithm": env.get("CIPHER_ALGORITHM", "AES-CBC-CTS"),
        "keySource": env.get("KEY_SOURCE", "PLAINTEXT"),
        "kmsKeyId": env.get("KMS_KEY_ID", ""),
        "awsRegion": env.get("AWS_REGION", ""),
    }
    try:
        urllib.request.urlopen(f"{TOKENIZATION_API_BASE}/healthz", timeout=2)
        status["serverStatus"] = "up"
    except Exception:  # noqa: BLE001 -- just means "not reachable"
        status["serverStatus"] = "down"
    return status


@app.post("/api/configure", include_in_schema=False)
def api_configure(payload: dict = Body(...)):
    try:
        apply_configuration(payload)
        return {"success": True}
    except subprocess.CalledProcessError as e:
        return JSONResponse(status_code=500, content={"success": False, "error": e.stderr or str(e)})
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"success": False, "error": str(e)})


def _tokenize_or_reidentify(target_path, payload):
    try:
        status, body = _forward_json(TOKENIZATION_API_BASE, target_path, payload)
        return JSONResponse(status_code=status, content=body)
    except urllib.error.HTTPError as e:
        return JSONResponse(status_code=e.code, content=json.loads(e.read().decode("utf-8")))
    except Exception as e:  # noqa: BLE001 -- e.g. connection refused if server is down
        return JSONResponse(status_code=502, content={"error": f"tokenization-api unreachable: {e}"})


@app.post("/api/tokenize", include_in_schema=False)
def api_tokenize(payload: dict = Body(...)):
    return _tokenize_or_reidentify("/v1/tokenize", payload)


@app.post("/api/reidentify", include_in_schema=False)
def api_reidentify(payload: dict = Body(...)):
    return _tokenize_or_reidentify("/v1/reidentify", payload)


@app.post("/api/db/connect", include_in_schema=False)
def api_db_connect(payload: dict = Body(...)):
    try:
        db_connect(payload)
        return {"success": True}
    except subprocess.TimeoutExpired:
        return JSONResponse(status_code=504, content={"success": False, "error": "Connection attempt timed out"})
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"success": False, "error": str(e)})


@app.post("/api/db/query", include_in_schema=False)
def api_db_query(payload: dict = Body(...)):
    try:
        return db_query(payload.get("sql"))
    except subprocess.TimeoutExpired:
        return JSONResponse(status_code=504, content={"error": "Query timed out"})
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.post("/api/sql/query", include_in_schema=False)
def api_sql_query(payload: dict = Body(...)):
    try:
        status, body = sql_proxy_query(payload)
        return JSONResponse(status_code=status, content=body)
    except urllib.error.HTTPError as e:
        return JSONResponse(status_code=e.code, content=json.loads(e.read().decode("utf-8")))
    except Exception as e:  # noqa: BLE001 -- e.g. connection refused if proxy is down
        return JSONResponse(status_code=502, content={"error": f"sql-interception-proxy unreachable: {e}"})


@app.post("/api/engine/sync", include_in_schema=False)
def api_engine_sync(payload: dict = Body(...)):
    try:
        result = engine_sync(payload)
        return {"success": True, **result}
    except subprocess.CalledProcessError as e:
        return JSONResponse(status_code=500, content={"success": False, "error": e.stderr or str(e)})
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"success": False, "error": str(e)})


@app.get("/api/applications", include_in_schema=False)
def api_list_applications():
    return {"applications": list_applications()}


@app.post("/api/applications", include_in_schema=False)
def api_add_application(payload: dict = Body(...)):
    try:
        return add_application(payload)
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.get("/api/environments", include_in_schema=False)
def api_list_environments():
    return {"environments": list_environments()}


@app.post("/api/environments", include_in_schema=False)
def api_add_environment(payload: dict = Body(...)):
    try:
        return add_environment(payload)
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.delete("/api/environments/{environment_id}", include_in_schema=False)
def api_delete_environment(environment_id: str):
    try:
        return delete_environment(environment_id)
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.get("/api/connectors", include_in_schema=False)
def api_list_connectors(environmentId: str):
    try:
        return {"connectors": list_connectors(environmentId)}
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.post("/api/connectors", include_in_schema=False)
def api_add_connector(payload: dict = Body(...)):
    try:
        return add_connector(payload)
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.get("/api/connectors/{connector_id}", include_in_schema=False)
def api_get_connector(connector_id: str):
    try:
        return get_connector(connector_id)
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.get("/api/algorithms", include_in_schema=False)
def api_list_algorithms():
    return {"algorithms": list_algorithms()}


@app.get("/api/connectors/{connector_id}/ruleset", include_in_schema=False)
def api_get_connector_ruleset(connector_id: str):
    try:
        return get_connector_ruleset(connector_id)
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.put("/api/connectors/{connector_id}/ruleset", include_in_schema=False)
def api_put_connector_ruleset(connector_id: str, payload: dict = Body(...)):
    try:
        fields = payload.get("fields") or {}
        return {"fields": save_connector_ruleset(connector_id, fields)}
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.get("/api/connectors/{connector_id}/messages", include_in_schema=False)
def api_get_connector_live_messages(connector_id: str, limit: int = 50):
    try:
        return get_connector_live_messages(connector_id, limit=limit)
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.get("/api/connectors/{connector_id}/workflows", include_in_schema=False)
def api_list_workflows(connector_id: str):
    return {"workflows": list_workflows(connector_id)}


@app.post("/api/workflows", include_in_schema=False)
def api_add_workflow(payload: dict = Body(...)):
    try:
        return add_workflow(payload)
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.post("/api/workflows/{workflow_id}/activate", include_in_schema=False)
def api_activate_workflow(workflow_id: str):
    try:
        return {"workflows": activate_workflow(workflow_id)}
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.delete("/api/workflows/{workflow_id}", include_in_schema=False)
def api_delete_workflow(workflow_id: str):
    try:
        return delete_workflow(workflow_id)
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.post("/api/kafka/produce", include_in_schema=False)
def api_kafka_produce(payload: dict = Body(...)):
    try:
        status, body = kafka_produce(payload)
        return JSONResponse(status_code=status, content=body)
    except urllib.error.HTTPError as e:
        return JSONResponse(status_code=e.code, content=json.loads(e.read().decode("utf-8")))
    except Exception as e:  # noqa: BLE001 -- e.g. connection refused if bridge is down
        return JSONResponse(status_code=502, content={"error": f"kafka-masking-bridge unreachable: {e}"})


@app.get("/api/kafka/messages", include_in_schema=False)
def api_kafka_messages():
    try:
        status, body = kafka_messages()
        return JSONResponse(status_code=status, content=body)
    except Exception as e:  # noqa: BLE001 -- e.g. connection refused if bridge is down
        return JSONResponse(status_code=502, content={"error": f"kafka-masking-bridge unreachable: {e}"})


# --- /v1/* documented proxy routes -- these ARE what /docs shows ---------------------------
# Each mirrors one real endpoint on tokenization-api/sql-interception-proxy/kafka-masking-bridge,
# reusing _forward_json() so behavior can't drift from the /api/* routes above.

TOKENIZATION_TAG = "Tokenization API (tokenization-api :4051)"
SQL_INTERCEPTION_TAG = "SQL Interception (sql-interception-proxy :4053)"
STREAMING_TAG = "Streaming (kafka-masking-bridge :4052)"

MASK_ENDPOINTS = (
    "full-name", "credit-card", "email", "first-name", "last-name", "date-shift", "segment-mapping",
)


def _batch_proxy(base_url, path, req: BatchRequest):
    try:
        status, body = _forward_json(base_url, path, req.model_dump())
        return JSONResponse(status_code=status, content=body)
    except urllib.error.HTTPError as e:
        return JSONResponse(status_code=e.code, content=json.loads(e.read().decode("utf-8")))
    except Exception as e:  # noqa: BLE001
        return JSONResponse(status_code=502, content={"error": f"{base_url} unreachable: {e}"})


@app.post("/v1/tokenize", response_model=BatchResponse, tags=[TOKENIZATION_TAG])
def v1_tokenize(req: BatchRequest):
    """Reversible tokenization -- {"values": [...]} -> tokens, null-preserving, per-row failures."""
    return _batch_proxy(TOKENIZATION_API_BASE, "/v1/tokenize", req)


@app.post("/v1/reidentify", response_model=BatchResponse, tags=[TOKENIZATION_TAG])
def v1_reidentify(req: BatchRequest):
    """Reverses /v1/tokenize -- tokens -> original values."""
    return _batch_proxy(TOKENIZATION_API_BASE, "/v1/reidentify", req)


for _mask_path in MASK_ENDPOINTS:
    def _make_mask_route(mask_path):
        def _route(req: BatchRequest):
            return _batch_proxy(TOKENIZATION_API_BASE, f"/v1/mask/{mask_path}", req)
        _route.__name__ = f"v1_mask_{mask_path.replace('-', '_')}"
        _route.__doc__ = f"One-way (non-reversible) {mask_path} masking -- fixed scheme, no config."
        return _route

    app.post(
        f"/v1/mask/{_mask_path}", response_model=BatchResponse, tags=[TOKENIZATION_TAG],
    )(_make_mask_route(_mask_path))


@app.get("/v1/healthz/tokenization-api", response_model=HealthStatus, tags=[TOKENIZATION_TAG])
def v1_healthz_tokenization_api():
    with urllib.request.urlopen(f"{TOKENIZATION_API_BASE}/healthz", timeout=5) as resp:
        return json.loads(resp.read())


@app.post("/v1/query", response_model=SqlQueryResponse, tags=[SQL_INTERCEPTION_TAG])
def v1_query(req: SqlQueryRequest):
    """Runs a read-only SELECT and masks known-sensitive columns (full_name/email/credit_card)
    transparently, by column label -- see SqlInterceptionHttpServer's javadoc for the SELECT-only
    guard and the aliased-column limitation."""
    try:
        status, body = _forward_json(SQL_PROXY_BASE, "/v1/query", req.model_dump())
        return JSONResponse(status_code=status, content=body)
    except urllib.error.HTTPError as e:
        return JSONResponse(status_code=e.code, content=json.loads(e.read().decode("utf-8")))
    except Exception as e:  # noqa: BLE001
        return JSONResponse(status_code=502, content={"error": f"sql-interception-proxy unreachable: {e}"})


@app.get("/v1/healthz/sql-interception-proxy", response_model=HealthStatus, tags=[SQL_INTERCEPTION_TAG])
def v1_healthz_sql_interception_proxy():
    with urllib.request.urlopen(f"{SQL_PROXY_BASE}/healthz", timeout=5) as resp:
        return json.loads(resp.read())


@app.post("/v1/kafka/produce", response_model=KafkaProduceAck, tags=[STREAMING_TAG])
def v1_kafka_produce(message: Dict[str, Any] = Body(..., description="Arbitrary JSON test message, e.g. {\"full_name\": \"Jane Doe\", \"email\": \"...\", \"credit_card\": \"...\"}")):
    """Produces a JSON message onto KAFKA_INPUT_TOPIC; kafka-masking-bridge tokenizes SENSITIVE_FIELDS
    and produces the result onto KAFKA_OUTPUT_TOPIC (see GET /v1/kafka/messages)."""
    try:
        status, body = _forward_json(KAFKA_BRIDGE_BASE, "/v1/kafka/produce", message)
        return JSONResponse(status_code=status, content=body)
    except urllib.error.HTTPError as e:
        return JSONResponse(status_code=e.code, content=json.loads(e.read().decode("utf-8")))
    except Exception as e:  # noqa: BLE001
        return JSONResponse(status_code=502, content={"error": f"kafka-masking-bridge unreachable: {e}"})


@app.get("/v1/kafka/messages", response_model=List[KafkaEnvelope], tags=[STREAMING_TAG])
def v1_kafka_messages():
    """Recently tokenized envelopes from KAFKA_OUTPUT_TOPIC, newest first (bounded in-memory buffer)."""
    try:
        status, body = kafka_messages()
        return JSONResponse(status_code=status, content=body)
    except Exception as e:  # noqa: BLE001
        return JSONResponse(status_code=502, content={"error": f"kafka-masking-bridge unreachable: {e}"})


@app.get("/v1/healthz/kafka-masking-bridge", response_model=HealthStatus, tags=[STREAMING_TAG])
def v1_healthz_kafka_masking_bridge():
    with urllib.request.urlopen(f"{KAFKA_BRIDGE_BASE}/healthz", timeout=5) as resp:
        return json.loads(resp.read())


if __name__ == "__main__":
    print(f"Demo UI on http://localhost:{DEMO_PORT}")
    print(f"API docs (Swagger UI) on http://localhost:{DEMO_PORT}/docs")
    uvicorn.run(app, host="0.0.0.0", port=DEMO_PORT)
