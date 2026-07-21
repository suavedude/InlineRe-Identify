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
  /api/connectors/{id}/rulesets + /api/rulesets(/{id}) (Custom Rulesets -- a user-authored, named
  column mapping, the only way to assign a connector's per-field/column algorithms; see
  _sync_connector_ruleset_from_columns() for how that assignment reaches connector["ruleset"]),
  /api/algorithms (this SDK's registered scheme ids, for the Rule Sets tab's dropdown),
  /api/connectors/{id}/messages (per-connector Live Messages detail view -- raw messages from the
  connector's topic paired with a live masked preview computed from its saved Rule Set),
  /api/connectors/{id}/workflows + /api/workflows(/{id}/activate) (named "run configurations" tied
  to one connector -- see the Workflows section's module comment above list_workflows() for the
  active/inactive exclusivity rule), /api/kafka/produce, /api/kafka/messages, /api/mcp-config (GET/PUT
  -- the sibling mcp-server/ package's own demoApiBase setting, edited from Settings > General >
  "MCP Server"; see get_mcp_config()/set_mcp_config()).
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
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import Body, FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastmcp import Client
from fastmcp.client.transports import PythonStdioTransport
from mcp.types import ElicitResult
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
# The mcp-server/ package (sibling directory) reads this file at its own startup to learn which
# demo backend to call -- see Settings > General > "MCP Server" panel and mcp-server/mcp_server.py's
# own _load_demo_api_base(). Reaching into a sibling directory like this mirrors the existing
# precedent of scripts/sync-engine-config.sh already being invoked from this same script.
MCP_CONFIG_FILE = REPO_ROOT / "mcp-server" / "mcp_config.json"
MCP_SERVER_SCRIPT = REPO_ROOT / "mcp-server" / "mcp_server.py"
# Monitor page's Test MCP Server card excludes these -- all three expect an interactive credential
# dialog (MCP elicitation) that this non-interactive test harness has no client-side dialog UI to
# satisfy. See _decline_elicitation() below for the defense-in-depth backstop if one is ever called
# anyway (e.g. a future tool that elicits without being added to this set).
EXCLUDED_MCP_TOOLS = {"attach_engine", "connect_database", "configure_crypto"}

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


def get_mcp_config():
    """The mcp-server/ package's own local config -- currently just which demo backend URL it
    should call, editable from Settings > General > "MCP Server" so a user doesn't have to hand-edit
    JSON. Read fresh every call (single-user local demo, same as ENV_STORE_FILE) and defaults to
    this same server's own default port if nothing's been saved yet."""
    if not MCP_CONFIG_FILE.exists():
        return {"demoApiBase": f"http://localhost:{DEMO_PORT}"}
    return json.loads(MCP_CONFIG_FILE.read_text())


def set_mcp_config(payload):
    demo_api_base = (payload.get("demoApiBase") or "").strip()
    if not demo_api_base:
        raise ValueError("demoApiBase is required")
    MCP_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    config = {"demoApiBase": demo_api_base.rstrip("/")}
    MCP_CONFIG_FILE.write_text(json.dumps(config, indent=2) + "\n")
    return config


async def _decline_elicitation(message, response_type, params, context):
    """Safety net for the Monitor page's Test MCP Server card: even though the dropdown already
    excludes EXCLUDED_MCP_TOOLS, this makes sure any tool call that unexpectedly triggers an
    elicitation dialog (there's no chat client here to render one) fails cleanly by declining,
    rather than hanging forever waiting for input that can never arrive."""
    return ElicitResult(action="decline")


def _mcp_test_client():
    """A fresh MCP client per test call -- spawns mcp-server/mcp_server.py as a real stdio
    subprocess (same as a chat client would), so the Monitor page's Test MCP Server card genuinely
    exercises the MCP tool layer instead of just re-calling this backend's own REST API directly.
    Uses sys.executable so the subprocess runs under the same Python environment as this server
    (and therefore has fastmcp/httpx installed)."""
    return Client(
        PythonStdioTransport(MCP_SERVER_SCRIPT, python_cmd=sys.executable),
        elicitation_handler=_decline_elicitation,
    )


async def list_mcp_tools():
    async with _mcp_test_client() as client:
        tools = await client.list_tools()
    return [
        {"name": t.name, "description": t.description, "inputSchema": t.inputSchema}
        for t in tools
        if t.name not in EXCLUDED_MCP_TOOLS
    ]


async def call_mcp_tool(tool_name, arguments):
    if tool_name in EXCLUDED_MCP_TOOLS:
        raise ValueError(
            f'"{tool_name}" requires an interactive credential dialog and can\'t be run from this '
            "test box -- try it from a real MCP chat client instead."
        )
    async with _mcp_test_client() as client:
        result = await client.call_tool(tool_name, arguments or {})
    return result.data if result.data is not None else [c.model_dump() for c in result.content]


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


def _check_healthz(name, base_url, timeout=3):
    """Live reachability probe for a downstream Java service exposing its own /healthz -- same
    urlopen pattern /api/status and the /v1/healthz/* passthrough routes already use individually
    (see TOKENIZATION_API_BASE's own check in api_status()), just shared here for the Monitor
    page's aggregate Health & Telemetry card. Times the round trip itself as a stand-in "latency"
    metric, since none of these services' /healthz bodies expose one of their own (verified live:
    they all just return {"status": "ok"})."""
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(f"{base_url}/healthz", timeout=timeout) as resp:
            body = json.loads(resp.read())
        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        return {"service": name, "status": "up", "detail": body.get("status", "healthy"), "latency_ms": latency_ms}
    except Exception as e:  # noqa: BLE001 -- any failure just means "not reachable"
        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        return {"service": name, "status": "down", "detail": str(e), "latency_ms": latency_ms}


def _check_kafka_ui_proxy():
    """Broker-level ping (GET /api/clusters, no cluster id/topic segment -- verified against a live
    kafka-ui-proxy: /api/clusters/local 404s since "local" alone isn't a valid sub-resource, but
    /api/clusters lists every configured cluster and its status). The topic-specific version of a
    similar request already exists in test_connector_kafka_health()."""
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(f"{KAFKA_UI_PROXY_BASE}/api/clusters", timeout=5) as resp:
            json.loads(resp.read())
        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        return {"service": "kafka-ui-proxy", "status": "up", "detail": "reachable", "latency_ms": latency_ms}
    except Exception as e:  # noqa: BLE001 -- unreachable, timeout, bad JSON, etc.
        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        return {"service": "kafka-ui-proxy", "status": "down", "detail": str(e), "latency_ms": latency_ms}


def _default_db_conn():
    """Reuses DB_CONN if the user has already connected via the SQL Functions panel; otherwise
    falls back to the same well-known docker-compose default credentials that panel is itself
    pre-filled with -- shared by every read-only Postgres helper below, none of which mutate
    DB_CONN itself."""
    return DB_CONN or {
        "host": "localhost", "port": "5432", "database": "dynamicmasking",
        "user": "dynamicmasking", "password": "dynamicmasking",
    }


def _check_postgres():
    start = time.perf_counter()
    try:
        result = _run_psql(_default_db_conn(), ["-c", "SELECT 1;"], timeout=5)
        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        if result.returncode != 0:
            return {"service": "postgres", "status": "down", "detail": result.stderr.strip() or "query failed", "latency_ms": latency_ms}
        return {"service": "postgres", "status": "up", "detail": "reachable", "latency_ms": latency_ms}
    except Exception as e:  # noqa: BLE001 -- docker not running, timeout, etc.
        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        return {"service": "postgres", "status": "down", "detail": str(e), "latency_ms": latency_ms}


def list_database_tables():
    """Backs the Add Ruleset modal's "Fetch Table Columns" button (step 1: list tables) -- every
    table in the public schema, so the user can pick one instead of typing a real table name from
    memory. Not connector-scoped: picking a table here is independent of any one connector's own
    preset tableName, so a single ruleset can be built from more than one table."""
    sql = "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name;"
    result = _run_psql(_default_db_conn(), ["--csv", "-c", sql], timeout=10)
    if result.returncode != 0:
        raise ValueError(result.stderr.strip() or "failed to list tables")
    rows = list(csv.reader(io.StringIO(result.stdout)))
    return [r[0] for r in rows[1:]] if len(rows) > 1 else []


def _fetch_table_columns(table_name):
    """Backs the Add Ruleset modal's "Fetch Table Columns" button (step 2: columns for the chosen
    table) -- real Postgres column names/types/sizes via information_schema, the same live
    introspection the old (removed) per-connector live-schema editor used, now scoped to whichever
    table the user picks rather than one fixed per-connector table. Each column also gets a
    suggested_algorithm the same way fetch_connector_topic_sample() already does for Kafka fields."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", table_name or ""):
        raise ValueError(f"'{table_name}' isn't a plausible table name")
    sql = (
        "SELECT column_name, data_type, COALESCE(character_maximum_length, numeric_precision) "
        f"FROM information_schema.columns WHERE table_name = '{table_name}' "
        "ORDER BY ordinal_position;"
    )
    result = _run_psql(_default_db_conn(), ["--csv", "-c", sql], timeout=10)
    if result.returncode != 0:
        raise ValueError(result.stderr.strip() or "failed to fetch columns")
    rows = list(csv.reader(io.StringIO(result.stdout)))
    if len(rows) <= 1:
        return []
    return [
        {
            "name": r[0],
            "dataType": r[1],
            "size": int(r[2]) if len(r) > 2 and r[2] else None,
            "suggested_algorithm": SUGGESTED_ALGORITHM_BY_FIELD.get(r[0]),
        }
        for r in rows[1:]
    ]


# Session-only counters (reset on restart, like every other in-memory demo state) backing the
# Health & Telemetry card's "Requests this session" line -- a stand-in for throughput since none
# of tokenization-api/sql-interception-proxy/kafka-masking-bridge's /healthz responses expose a
# request count or rate of their own (verified live: they're just {"status": "ok"}). This counts
# calls made through *this* demo backend, not the downstream services' total traffic.
REQUEST_COUNTS = {"tokenize": 0, "sql_query": 0, "kafka_produce": 0}


def get_health_telemetry():
    """Backs the Monitor page's Health & Telemetry card -- one row per API/microservice this demo
    depends on, plus this session's request counts. delphix-engine and mcp-server are deliberately
    never "down" and never get a latency_ms: the engine is an opt-in attach (not attaching isn't a
    failure), and mcp-server runs over stdio with no network-probable listener at all (see
    mcp-server/mcp_server.py) -- both report "unknown" with an explanatory detail rather than a
    fabricated status or a fabricated latency."""
    engine_status = get_engine_attach_status()
    services = [
        _check_healthz("tokenization-api", TOKENIZATION_API_BASE),
        _check_healthz("sql-interception-proxy", SQL_PROXY_BASE),
        _check_healthz("kafka-masking-bridge", KAFKA_BRIDGE_BASE),
        _check_kafka_ui_proxy(),
        _check_postgres(),
        {
            "service": "delphix-engine",
            "status": "up" if engine_status["attached"] else "unknown",
            "detail": (f"attached to {engine_status['host']} as {engine_status['username']}"
                       if engine_status["attached"] else "not attached"),
            "latency_ms": None,
        },
        {
            "service": "mcp-server",
            "status": "unknown",
            "detail": ("stdio transport has no live network probe -- use the Test MCP Server card "
                       "below, or the AI Integration settings tab"),
            "latency_ms": None,
        },
    ]
    return {
        "services": services,
        "requestCounts": {
            "tokenize": REQUEST_COUNTS["tokenize"],
            "sqlQuery": REQUEST_COUNTS["sql_query"],
            "kafkaProduce": REQUEST_COUNTS["kafka_produce"],
        },
    }


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
        return {"applications": [], "environments": [], "connectors": [], "workflows": [], "rulesets": []}
    store = json.loads(ENV_STORE_FILE.read_text())
    store.setdefault("connectors", [])  # tolerate a store written before connectors existed
    store.setdefault("workflows", [])  # tolerate a store written before workflows existed
    store.setdefault("rulesets", [])  # tolerate a store written before custom rulesets existed
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
    store["rulesets"] = [r for r in store["rulesets"] if str(r["connectorId"]) not in removed_connector_ids]
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


def delete_connector(connector_id):
    store = _read_store()
    _find_connector(store, connector_id)  # raises if not found
    attached_workflows = [w for w in store["workflows"] if str(w["connectorId"]) == str(connector_id)]
    if attached_workflows:
        raise ValueError(
            f"Cannot delete: {len(attached_workflows)} workflow(s) still reference this connector "
            "— delete them first."
        )
    store["connectors"] = [c for c in store["connectors"] if str(c["id"]) != str(connector_id)]
    _write_store(store)
    return {"deleted": connector_id}


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


def _algorithm_udf(algorithm_name):
    """The real Postgres UDF for an algorithm (see docker/postgres/udf.sql), derived from the same
    ALGORITHM_TO_MASK_PATH/TOKENIZATION_ALGORITHMS maps _apply_mask_batch() already uses -- not
    guessed. DATE-REDACT/NUMBER-REDACT/STRING-REDACT genuinely have no SQL UDF (no HTTP endpoint
    either, see ALGORITHM_TO_MASK_PATH's comment), so those return None rather than a fabricated name."""
    if algorithm_name in ALGORITHM_TO_MASK_PATH:
        return f"mask_{ALGORITHM_TO_MASK_PATH[algorithm_name].replace('-', '')}()"
    if algorithm_name in TOKENIZATION_ALGORITHMS:
        return "tokenize() / reidentify()"
    return None


def list_algorithms():
    return [{**algo, "udf": _algorithm_udf(algo["algorithm_name"])} for algo in ALGORITHM_REGISTRY]


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


def test_connector_kafka_health(connector_id):
    """Real reachability check (Connectors tab's "Test" action) -- calls kafka-ui-proxy's
    topic-details endpoint (not the messages stream _fetch_messages() uses) so a missing topic or
    an unreachable kafka-ui-proxy is distinguishable from "topic exists but has no messages yet."
    Never raises: always returns a dict the UI can render either way."""
    store = _read_store()
    connector = _find_connector(store, connector_id)
    if connector["category"] != "KAFKA":
        raise ValueError("Test is only available for Kafka connectors")
    topic = connector.get("topicName") or "dynamicmasking.demo.output"
    url = f"{KAFKA_UI_PROXY_BASE}/api/clusters/local/topics/{urllib.parse.quote(topic, safe='')}"
    try:
        with urllib.request.urlopen(url, timeout=8) as resp:
            body = json.loads(resp.read())
        partitions = len(body.get("partitions", [])) or body.get("partitionCount")
        return {"healthy": True, "topic": topic, "partitions": partitions}
    except urllib.error.HTTPError as e:
        detail = "topic not found" if e.code == 404 else f"HTTP {e.code} from kafka-ui-proxy"
        return {"healthy": False, "topic": topic, "detail": detail}
    except Exception as e:  # noqa: BLE001 -- kafka-ui-proxy unreachable, timeout, bad JSON, etc.
        return {"healthy": False, "topic": topic, "detail": f"kafka-ui-proxy unreachable: {e}"}


def fetch_connector_topic_sample(connector_id):
    """Backs the Add Ruleset modal's "Fetch Topic Message" button -- one live sample message from
    a KAFKA connector's real topic, used to prepopulate column rows (field name + a suggested
    algorithm) instead of starting from a blank table."""
    store = _read_store()
    connector = _find_connector(store, connector_id)
    if connector["category"] != "KAFKA":
        raise ValueError("Fetch Topic Message is only available for KAFKA connectors")
    topic = connector.get("topicName") or "dynamicmasking.demo.output"
    messages = _fetch_messages(topic, limit=1)
    if not messages:
        raise ValueError(f"No messages found on topic '{topic}' yet.")
    sample = messages[0]
    # kafka-masking-bridge's own output topic wraps the actual fields inside "original"/
    # "tokenized" (see KafkaMaskingBridge.tokenizeMessage) -- unwrap so suggested column names are
    # the real field names (full_name/email/credit_card), not the envelope's own keys.
    if isinstance(sample, dict) and "original" in sample and "tokenized" in sample:
        sample = sample["original"]
    fields = [
        {"name": k, "suggested_algorithm": SUGGESTED_ALGORITHM_BY_FIELD.get(k)}
        for k in sample.keys()
    ]
    return {"topic": topic, "sample": sample, "fields": fields}


def get_connector_live_messages(connector_id, limit=50):
    """Backs the per-connector Live Messages detail view for any connector whose topic isn't
    kafka-masking-bridge's own output topic (which /api/kafka/messages already serves, pre-joined
    into original/tokenized envelopes) -- e.g. EDI270, a raw source topic with no masking job.
    Pairs each raw message with a masked preview computed live from the connector's saved Rule Set
    (see _sync_connector_ruleset_from_columns()), one batched call per ruleset-assigned field
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


def _sync_connector_ruleset_from_columns(connector, columns):
    """Keeps the real masked-preview in get_connector_live_messages() working now that Custom
    Rulesets (below), not a live per-field editor, are the only way to assign algorithms -- mirrors
    the old editor's save shape ({fieldName: algorithm}, only for columns that have one assigned)
    so nothing downstream of connector["ruleset"] needs to change."""
    connector["ruleset"] = {c["name"]: c["algorithm"] for c in columns if c.get("algorithm")}


# --- Workflows (Workflows tab) ---------------------------------------------------------------
# A connector already has exactly one Ruleset (connector["ruleset"], above). A Workflow is a named
# "run configuration" against that (connector, ruleset) pair -- many can exist, but at most one is
# ever `active` per connector (enforced in activate_workflow()). NOTE: `active` is bookkeeping --
# which workflow *would* run -- not a live process being started/stopped; this demo has no
# generalized masking-workflow execution engine.
def list_workflows(connector_id):
    return [w for w in _read_store()["workflows"] if str(w["connectorId"]) == str(connector_id)]


def _validate_workflow_ruleset_id(store, connector_id, ruleset_id):
    """A workflow's rulesetId (if given) must be a real Custom Ruleset belonging to the same
    connector -- same "confirm it exists" precedent as connectorId, plus the one connector-scoping
    check that's actually meaningful here (unlike Custom Rulesets' own connectorId, which is only
    scoped by the frontend picker -- see the module comment above _validate_ruleset_columns())."""
    if ruleset_id is None:
        return None
    ruleset = _find_ruleset(store, ruleset_id)  # raises if it doesn't exist
    if str(ruleset["connectorId"]) != str(connector_id):
        raise ValueError("rulesetId must belong to the selected connector")
    return ruleset_id


def add_workflow(payload):
    connector_id = payload.get("connectorId")
    name = (payload.get("name") or "").strip()
    description = (payload.get("description") or "").strip()
    if connector_id is None or not name:
        raise ValueError("connectorId and name are required")
    store = _read_store()
    _find_connector(store, connector_id)  # raises if the connector doesn't exist
    ruleset_id = _validate_workflow_ruleset_id(store, connector_id, payload.get("rulesetId"))
    next_id = max([w["id"] for w in store["workflows"]], default=0) + 1
    workflow = {
        "id": next_id,
        "connectorId": connector_id,
        "rulesetId": ruleset_id,
        "name": name,
        "description": description or None,
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


def update_workflow(workflow_id, payload):
    store = _read_store()
    workflow = _find_workflow(store, workflow_id)
    if "connectorId" in payload and payload["connectorId"] is not None:
        _find_connector(store, payload["connectorId"])  # raises if the connector doesn't exist
        workflow["connectorId"] = payload["connectorId"]
    if "name" in payload and payload["name"] is not None:
        name = payload["name"].strip()
        if not name:
            raise ValueError("name cannot be blank")
        workflow["name"] = name
    if "description" in payload:
        workflow["description"] = (payload["description"] or "").strip() or None
    if "rulesetId" in payload:
        workflow["rulesetId"] = _validate_workflow_ruleset_id(store, workflow["connectorId"], payload["rulesetId"])
    _write_store(store)
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


# --- Custom Rulesets (Rule Sets tab) -----------------------------------------------------------
# A user-authored, named column mapping -- NOT derived from a connector's live schema (unlike
# connector["ruleset"] above, which is auto-populated from the real Kafka topic/Postgres table).
# Rows are freeform: {name, dataType, algorithm}, dataType is plain text since there's no live
# schema to source a real one from. The connector a Ruleset points at is scoped to "the current
# environment" purely by the frontend populating the picker from currentConnectors (already
# environment-scoped everywhere else in this app) -- no separate backend cross-check needed beyond
# confirming the connector exists, same as add_workflow()'s existing connectorId validation.
def _validate_ruleset_columns(columns):
    if not isinstance(columns, list):
        raise ValueError("columns must be a list")
    cleaned = []
    for col in columns:
        name = (col.get("name") or "").strip()
        if not name:
            raise ValueError("every column needs a name")
        cleaned.append({
            "name": name,
            "table": (col.get("table") or "").strip() or None,
            "dataType": (col.get("dataType") or "").strip() or None,
            "size": (col.get("size") or "").strip() or None,
            "algorithm": col.get("algorithm") or None,
        })
    return cleaned


def list_rulesets(connector_id):
    return [r for r in _read_store()["rulesets"] if str(r["connectorId"]) == str(connector_id)]


def add_ruleset(payload):
    connector_id = payload.get("connectorId")
    name = (payload.get("name") or "").strip()
    if connector_id is None or not name:
        raise ValueError("connectorId and name are required")
    store = _read_store()
    connector = _find_connector(store, connector_id)  # raises if the connector doesn't exist
    columns = _validate_ruleset_columns(payload.get("columns") or [])
    next_id = max([r["id"] for r in store["rulesets"]], default=0) + 1
    ruleset = {
        "id": next_id,
        "connectorId": connector_id,
        "name": name,
        "columns": columns,
        "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    store["rulesets"].append(ruleset)
    _sync_connector_ruleset_from_columns(connector, columns)
    _write_store(store)
    return ruleset


def _find_ruleset(store, ruleset_id):
    ruleset = next((r for r in store["rulesets"] if str(r["id"]) == str(ruleset_id)), None)
    if ruleset is None:
        raise ValueError(f"No ruleset with id {ruleset_id}")
    return ruleset


def get_ruleset(ruleset_id):
    return _find_ruleset(_read_store(), ruleset_id)


def update_ruleset(ruleset_id, payload):
    store = _read_store()
    ruleset = _find_ruleset(store, ruleset_id)
    if "connectorId" in payload and payload["connectorId"] is not None:
        _find_connector(store, payload["connectorId"])  # raises if the connector doesn't exist
        ruleset["connectorId"] = payload["connectorId"]
    if "name" in payload and payload["name"] is not None:
        name = payload["name"].strip()
        if not name:
            raise ValueError("name cannot be blank")
        ruleset["name"] = name
    if "columns" in payload and payload["columns"] is not None:
        ruleset["columns"] = _validate_ruleset_columns(payload["columns"])
    connector = _find_connector(store, ruleset["connectorId"])
    _sync_connector_ruleset_from_columns(connector, ruleset["columns"])
    _write_store(store)
    return ruleset


def delete_ruleset(ruleset_id):
    store = _read_store()
    _find_ruleset(store, ruleset_id)  # raises if not found
    store["rulesets"] = [r for r in store["rulesets"] if str(r["id"]) != str(ruleset_id)]
    _write_store(store)
    return {"deleted": ruleset_id}


# Global cross-environment view for the Settings "All Rule Sets" table -- joins each workflow's
# connectorId through connectors -> environments so the table can show/link the owning environment.
def list_all_workflows():
    store = _read_store()
    connectors_by_id = {str(c["id"]): c for c in store["connectors"]}
    environments_by_id = {str(e["id"]): e for e in store["environments"]}
    enriched = []
    for workflow in store["workflows"]:
        connector = connectors_by_id.get(str(workflow["connectorId"]))
        environment = environments_by_id.get(str(connector["environmentId"])) if connector else None
        enriched.append({
            **workflow,
            "connectorName": connector["name"] if connector else None,
            "sourceType": connector["category"] if connector else None,
            "metadata": connector["type"] if connector else None,
            "environmentId": environment["id"] if environment else None,
            "environmentName": environment["name"] if environment else "(deleted environment)",
        })
    return sorted(enriched, key=lambda w: w["createdAt"], reverse=True)


# --- Delphix Masking Engine key sync (Settings tab) ---------------------------------------
# NOTE: this talks to a live Delphix Masking Engine's REST API. The login step (POST {base}/login
# with {"username", "password"} -> a session token in the response body's "Authorization" field,
# sent back as the "Authorization" header on subsequent calls) -- confirmed directly against a
# live engine (2026.2.0.0): POST /masking/api/login returns {"Authorization": "<token>"}, and
# GET /masking/api/algorithms with that token as the Authorization header returns
# {"_pageInfo": {...}, "responseList": [...]}, which the responseList-or-raw-list unwrap below
# already handles. The key-file lookup in _engine_find_key() below is still best-effort/unverified
# -- if that specific step fails, check its field-name assumptions against your engine's actual
# /file-downloads response shape.
ENGINE_API_BASE_PATH = os.environ.get("ENGINE_API_BASE_PATH", "/masking/api")


def _normalize_engine_host(host):
    """Tolerates a pasted full URL (e.g. "https://engine.example.com/") in the Engine Host field
    instead of a bare hostname -- without this, a scheme prefix produces a malformed
    "https://https://..." URL whose netloc urllib parses as the literal string "https:", which
    fails DNS resolution with a cryptic getaddrinfo error instead of a clear one."""
    host = host.strip()
    host = re.sub(r"^https?://", "", host, flags=re.IGNORECASE)
    return host.rstrip("/")


# Delphix Masking Engine deployments (especially on-prem/internal ones, like most real customer
# installs) very commonly run on a self-signed certificate -- there's no CA to verify against, so
# the default urlopen() behavior fails every request with CERTIFICATE_VERIFY_FAILED before this
# feature can do anything useful. This is a user-specified engine the operator already trusts by
# typing its host/credentials in, so skipping cert verification here (not anywhere else in this
# file) is the same tradeoff Delphix's own CLI/tools make for self-signed engines.
_ENGINE_SSL_CONTEXT = ssl.create_default_context()
_ENGINE_SSL_CONTEXT.check_hostname = False
_ENGINE_SSL_CONTEXT.verify_mode = ssl.CERT_NONE


def _engine_request(host, method, path, session=None, body=None):
    url = f"https://{_normalize_engine_host(host)}{ENGINE_API_BASE_PATH}{path}"
    headers = {"Content-Type": "application/json"}
    if session:
        headers["Authorization"] = session
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15, context=_ENGINE_SSL_CONTEXT) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise ValueError(
            f"Engine request {method} {path} failed (HTTP {e.code}): "
            f"{e.read().decode('utf-8', 'replace')}"
        )


def _engine_login(host, username, password):
    resp = _engine_request(host, "POST", "/login", body={"username": username, "password": password})
    session = resp.get("Authorization")
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


# In-memory only (never written to demo/environments.json or .env) -- a session token isn't worth
# persisting to disk for a single-user local demo, same reasoning already applied to _read_store().
# "Attach to a Delphix Engine" logs in once and the Rule Sets / Sync Keys panels both reuse this.
_ENGINE_SESSION = {"host": None, "username": None, "session": None}


def attach_engine(payload):
    host = _normalize_engine_host(payload.get("host") or "")
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    if not host or not username or not password:
        raise ValueError("host, username, and password are all required")
    session = _engine_login(host, username, password)
    _ENGINE_SESSION["host"] = host
    _ENGINE_SESSION["username"] = username
    _ENGINE_SESSION["session"] = session
    return {"host": host, "username": username, "attached": True}


def get_engine_attach_status():
    return {
        "host": _ENGINE_SESSION["host"],
        "username": _ENGINE_SESSION["username"],
        "attached": _ENGINE_SESSION["session"] is not None,
    }


def _require_engine_attached():
    if not _ENGINE_SESSION["session"]:
        raise ValueError('Not attached to an engine yet -- use "Attach to a Delphix Engine" above first.')
    return _ENGINE_SESSION["host"], _ENGINE_SESSION["session"]


def list_engine_database_rulesets():
    """Best-effort, same caveat as _engine_find_key(): the real Delphix Masking API's
    GET /database-rulesets response envelope/field names haven't been verified against a live
    engine from this codebase -- if the shape differs, adjust the responseList-or-raw-list unwrap
    below to match your engine's actual response."""
    host, session = _require_engine_attached()
    result = _engine_request(host, "GET", "/database-rulesets", session=session)
    return result.get("responseList", result) if isinstance(result, dict) else result


def engine_export_ruleset(ruleset_id):
    """Best-effort, same caveat as list_engine_database_rulesets(): the real Delphix Masking API's
    GET /database-rulesets/{id} sub-resource hasn't been verified against a live engine from this
    codebase -- if it 404s on your engine version, this is the line to adjust."""
    host, session = _require_engine_attached()
    return _engine_request(host, "GET", f"/database-rulesets/{ruleset_id}", session=session)


def engine_sync_key():
    if not IS_LOCAL_TARGET:
        raise ValueError(
            f"TOKENIZATION_API_BASE is set to {TOKENIZATION_API_BASE}, not a local address -- "
            "Sync Key from Engine only works against the local docker-compose stack (it runs "
            "`docker compose` on this machine, same as Apply Configuration)."
        )

    host, session = _require_engine_attached()
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


@app.get("/logo.png", include_in_schema=False)
def logo():
    return FileResponse(DEMO_DIR / "logo.png", media_type="image/png")


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


@app.get("/api/health", include_in_schema=False)
def api_health():
    return get_health_telemetry()


@app.get("/api/mcp-config", include_in_schema=False)
def api_get_mcp_config():
    return get_mcp_config()


@app.put("/api/mcp-config", include_in_schema=False)
def api_set_mcp_config(payload: dict = Body(...)):
    try:
        return set_mcp_config(payload)
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.get("/api/mcp/tools", include_in_schema=False)
async def api_list_mcp_tools():
    try:
        return {"tools": await list_mcp_tools()}
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.post("/api/mcp/call", include_in_schema=False)
async def api_call_mcp_tool(payload: dict = Body(...)):
    try:
        tool_name = payload.get("tool")
        if not tool_name:
            raise ValueError("tool is required")
        return {"result": await call_mcp_tool(tool_name, payload.get("args") or {})}
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


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
    REQUEST_COUNTS["tokenize"] += 1
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


@app.get("/api/db/tables", include_in_schema=False)
def api_list_database_tables():
    try:
        return {"tables": list_database_tables()}
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.get("/api/db/tables/{table_name}/columns", include_in_schema=False)
def api_fetch_table_columns(table_name: str):
    try:
        return {"columns": _fetch_table_columns(table_name)}
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.post("/api/sql/query", include_in_schema=False)
def api_sql_query(payload: dict = Body(...)):
    REQUEST_COUNTS["sql_query"] += 1
    try:
        status, body = sql_proxy_query(payload)
        return JSONResponse(status_code=status, content=body)
    except urllib.error.HTTPError as e:
        return JSONResponse(status_code=e.code, content=json.loads(e.read().decode("utf-8")))
    except Exception as e:  # noqa: BLE001 -- e.g. connection refused if proxy is down
        return JSONResponse(status_code=502, content={"error": f"sql-interception-proxy unreachable: {e}"})


@app.post("/api/engine/attach", include_in_schema=False)
def api_attach_engine(payload: dict = Body(...)):
    try:
        return attach_engine(payload)
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.get("/api/engine/attach-status", include_in_schema=False)
def api_engine_attach_status():
    return get_engine_attach_status()


@app.get("/api/engine/database-rulesets", include_in_schema=False)
def api_engine_database_rulesets():
    try:
        return {"rulesets": list_engine_database_rulesets()}
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.get("/api/engine/database-rulesets/{ruleset_id}/export", include_in_schema=False)
def api_engine_export_ruleset(ruleset_id: str):
    try:
        return engine_export_ruleset(ruleset_id)
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.post("/api/engine/sync-key", include_in_schema=False)
def api_engine_sync_key():
    try:
        result = engine_sync_key()
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


@app.delete("/api/connectors/{connector_id}", include_in_schema=False)
def api_delete_connector(connector_id: str):
    try:
        return delete_connector(connector_id)
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.get("/api/connectors/{connector_id}/kafka-health", include_in_schema=False)
def api_connector_kafka_health(connector_id: str):
    try:
        return test_connector_kafka_health(connector_id)
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.get("/api/connectors/{connector_id}/topic-sample", include_in_schema=False)
def api_connector_topic_sample(connector_id: str):
    try:
        return fetch_connector_topic_sample(connector_id)
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.get("/api/algorithms", include_in_schema=False)
def api_list_algorithms():
    return {"algorithms": list_algorithms()}


@app.get("/api/connectors/{connector_id}/messages", include_in_schema=False)
def api_get_connector_live_messages(connector_id: str, limit: int = 50):
    try:
        return get_connector_live_messages(connector_id, limit=limit)
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.get("/api/connectors/{connector_id}/workflows", include_in_schema=False)
def api_list_workflows(connector_id: str):
    return {"workflows": list_workflows(connector_id)}


@app.get("/api/workflows", include_in_schema=False)
def api_list_all_workflows():
    return {"workflows": list_all_workflows()}


@app.post("/api/workflows", include_in_schema=False)
def api_add_workflow(payload: dict = Body(...)):
    try:
        return add_workflow(payload)
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.put("/api/workflows/{workflow_id}", include_in_schema=False)
def api_update_workflow(workflow_id: str, payload: dict = Body(...)):
    try:
        return update_workflow(workflow_id, payload)
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


@app.get("/api/connectors/{connector_id}/rulesets", include_in_schema=False)
def api_list_rulesets(connector_id: str):
    return {"rulesets": list_rulesets(connector_id)}


@app.post("/api/rulesets", include_in_schema=False)
def api_add_ruleset(payload: dict = Body(...)):
    try:
        return add_ruleset(payload)
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.get("/api/rulesets/{ruleset_id}", include_in_schema=False)
def api_get_ruleset(ruleset_id: str):
    try:
        return get_ruleset(ruleset_id)
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.put("/api/rulesets/{ruleset_id}", include_in_schema=False)
def api_update_ruleset(ruleset_id: str, payload: dict = Body(...)):
    try:
        return update_ruleset(ruleset_id, payload)
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.delete("/api/rulesets/{ruleset_id}", include_in_schema=False)
def api_delete_ruleset(ruleset_id: str):
    try:
        return delete_ruleset(ruleset_id)
    except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.post("/api/kafka/produce", include_in_schema=False)
def api_kafka_produce(payload: dict = Body(...)):
    REQUEST_COUNTS["kafka_produce"] += 1
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
