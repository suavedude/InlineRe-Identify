#!/usr/bin/env python3
"""
MCP server for the DynamicMasking demo -- lets any MCP-capable chat client (Claude Desktop, Claude
Code, etc.) drive the demo's Environments/Connectors/Custom Rulesets/Workflows/Algorithms/SQL and
Continuous Compliance Engine integration conversationally, instead of only through the browser UI.

This is a thin HTTP client: every tool below just calls one of demo/server.py's existing REST
endpoints (see that file's own module docstring for the full route list). It makes zero changes to
demo/server.py's behavior -- the two processes run side by side, exactly like the browser UI and
demo/server.py already do. demo/server.py must be running (default http://localhost:4041) for any
tool call here to succeed.

Two hard rules this file follows, both non-negotiable design decisions (not just style choices):

1. No destructive calls toward the attached (real) Delphix engine. Every engine tool is read-only,
   attach (login), or pull-from-engine (sync_engine_key reads the engine's key into *this demo's
   own* local .env, never back to the engine) -- mirrored exactly from demo/server.py's own
   _engine_request() call sites, every one of which is GET or the initial login POST. No tool here
   sends PUT/DELETE/PATCH to the engine, and none should be added without deliberate sign-off.

2. Real secrets (engine password, Postgres password, AWS/KMS credentials) are never accepted as
   plain tool arguments -- an LLM would otherwise see and could echo them in the conversation
   transcript / MCP logs like any other argument. Instead, tools that need a secret call
   `ctx.elicit(...)` to pop an actual input dialog in the MCP client and collect it directly. This
   requires the connected client to support MCP's elicitation capability; if it doesn't, FastMCP
   raises a clear error rather than silently falling back to a plain-argument prompt.
"""

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import httpx
from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError

# ============================================================================================
# Config: where demo/server.py is reachable. Resolution order: mcp_config.json (written by the
# demo's own Settings > General > "MCP Server" panel) -> DEMO_API_BASE env var -> the same
# http://localhost:4041 default demo/server.py itself listens on.
# ============================================================================================
MCP_CONFIG_FILE = Path(__file__).resolve().parent / "mcp_config.json"


def _load_demo_api_base() -> str:
    if MCP_CONFIG_FILE.exists():
        try:
            config = json.loads(MCP_CONFIG_FILE.read_text())
            base = (config.get("demoApiBase") or "").strip()
            if base:
                return base.rstrip("/")
        except (json.JSONDecodeError, OSError):
            pass  # fall through to the env var / default -- a bad config file shouldn't crash startup
    return os.environ.get("DEMO_API_BASE", "http://localhost:4041").rstrip("/")


DEMO_API_BASE = _load_demo_api_base()

mcp = FastMCP(
    name="DynamicMasking",
    instructions=(
        "Tools for the DynamicMasking demo (Delphix Continuous Compliance-style demo app): "
        "Environments, Connectors, Custom Rulesets, Workflows, Algorithms, SQL/tokenization test "
        "calls, and the Continuous Compliance Engine integration (attach/list/export/sync only -- "
        "never destructive toward the real engine). The demo backend must be running at "
        f"{DEMO_API_BASE} for any of these to work."
    ),
)

_client = httpx.AsyncClient(base_url=DEMO_API_BASE, timeout=30.0)


async def _call(method: str, path: str, **kwargs: Any) -> Any:
    """Shared request helper -- surfaces demo/server.py's own {"error": "..."} messages as clean
    ToolErrors instead of raw HTTP/JSON details, and gives one clear message if the demo backend
    isn't reachable at all (the most likely first-run failure)."""
    try:
        resp = await _client.request(method, path, **kwargs)
    except httpx.ConnectError as e:
        raise ToolError(
            f"Can't reach the DynamicMasking demo backend at {DEMO_API_BASE} -- "
            f"is `python3 demo/server.py` running? ({e})"
        ) from e
    try:
        body = resp.json()
    except ValueError:
        body = {"error": resp.text or f"HTTP {resp.status_code} with no body"}
    if resp.status_code >= 400:
        raise ToolError(body.get("error") or f"Request failed (HTTP {resp.status_code}): {body}")
    return body


# ============================================================================================
# Applications / Environments
# ============================================================================================
@mcp.tool()
async def list_environments() -> list[dict]:
    """List every Environment in the demo (id, application, name, purpose, createdAt)."""
    return (await _call("GET", "/api/environments"))["environments"]


@mcp.tool()
async def create_environment(application: str, name: str, purpose: str) -> dict:
    """Create a new Environment. `purpose` must be exactly one of "Streaming", "Tokenization", or
    "SQL Interception" -- it determines what kind of Connectors this environment can hold."""
    return await _call("POST", "/api/environments", json={
        "application": application, "name": name, "purpose": purpose,
    })


@mcp.tool()
async def delete_environment(environment_id: str) -> dict:
    """Delete an Environment and cascade-delete its Connectors, Workflows, and Custom Rulesets."""
    return await _call("DELETE", f"/api/environments/{environment_id}")


@mcp.tool()
async def list_applications() -> list[str]:
    """List every Application name used to group Environments in the demo."""
    return (await _call("GET", "/api/applications"))["applications"]


@mcp.tool()
async def create_application(name: str) -> dict:
    """Create a new Application name (a grouping label for Environments)."""
    return await _call("POST", "/api/applications", json={"name": name})


# ============================================================================================
# Connectors
# ============================================================================================
@mcp.tool()
async def list_connectors(environment_id: str) -> list[dict]:
    """List every Connector in one Environment."""
    return (await _call("GET", "/api/connectors", params={"environmentId": environment_id}))["connectors"]


@mcp.tool()
async def get_connector(connector_id: str) -> dict:
    """Get one Connector's full detail by id."""
    return await _call("GET", f"/api/connectors/{connector_id}")


@mcp.tool()
async def create_connector(
    environment_id: str,
    name: str,
    type: str,
    topic_name: Optional[str] = None,
    bootstrap_servers: Optional[str] = None,
    table_name: Optional[str] = None,
) -> dict:
    """Create a Connector inside an Environment. For a Streaming environment's Kafka connector,
    pass topic_name and bootstrap_servers (e.g. "kafka:19092"); stream_type is always "kafka" in
    this demo. For a Tokenization/SQL Interception environment's connector, optionally pass
    table_name (defaults to "customers", the only demo table, if left blank)."""
    payload: dict[str, Any] = {"environmentId": environment_id, "name": name, "type": type}
    if topic_name is not None:
        payload["topicName"] = topic_name
    if bootstrap_servers is not None:
        payload["bootstrapServers"] = bootstrap_servers
        payload["streamType"] = "kafka"
    if table_name is not None:
        payload["tableName"] = table_name
    return await _call("POST", "/api/connectors", json=payload)


@mcp.tool()
async def delete_connector(connector_id: str) -> dict:
    """Delete a Connector (and, on the demo side, its Workflows/Custom Rulesets)."""
    return await _call("DELETE", f"/api/connectors/{connector_id}")


@mcp.tool()
async def test_connector_kafka_health(connector_id: str) -> dict:
    """Check whether a KAFKA connector's real topic is reachable (via kafka-ui-proxy) and how many
    partitions it has. Only valid for KAFKA-category connectors."""
    return await _call("GET", f"/api/connectors/{connector_id}/kafka-health")


@mcp.tool()
async def fetch_connector_topic_sample(connector_id: str) -> dict:
    """Fetch one live sample message from a KAFKA connector's real topic, plus a suggested Delphix
    Algorithm per field (based on the field name) -- useful for building a Custom Ruleset for that
    connector from real data. Only valid for KAFKA-category connectors."""
    return await _call("GET", f"/api/connectors/{connector_id}/topic-sample")


# ============================================================================================
# Custom Rulesets -- named, hand-built column mappings (Column Name/Data Type/Size/Algorithm),
# NOT derived from a connector's live schema.
# ============================================================================================
@mcp.tool()
async def list_rulesets(connector_id: str) -> list[dict]:
    """List every Custom Ruleset belonging to one Connector."""
    return (await _call("GET", f"/api/connectors/{connector_id}/rulesets"))["rulesets"]


@mcp.tool()
async def get_ruleset(ruleset_id: str) -> dict:
    """Get one Custom Ruleset's full detail (name, connectorId, columns) by id."""
    return await _call("GET", f"/api/rulesets/{ruleset_id}")


@mcp.tool()
async def create_ruleset(connector_id: str, name: str, columns: list[dict]) -> dict:
    """Create a Custom Ruleset on a Connector. Each entry in `columns` is a dict with keys "name"
    (required), and optionally "dataType", "size" (both freeform text), and "algorithm" (must be a
    real algorithm_name from list_algorithms(), e.g. "EMAIL-MASK", "FIRST-NAME-LOOKUP",
    "AES-CBC-CTS" -- omit or use null for a column that should pass through unmasked)."""
    return await _call("POST", "/api/rulesets", json={
        "connectorId": connector_id, "name": name, "columns": columns,
    })


@mcp.tool()
async def update_ruleset(
    ruleset_id: str,
    connector_id: Optional[str] = None,
    name: Optional[str] = None,
    columns: Optional[list[dict]] = None,
) -> dict:
    """Update a Custom Ruleset -- rename it, reassign it to a different connector_id, and/or
    replace its columns entirely (same column shape as create_ruleset). Omit any field to leave it
    unchanged."""
    payload: dict[str, Any] = {}
    if connector_id is not None:
        payload["connectorId"] = connector_id
    if name is not None:
        payload["name"] = name
    if columns is not None:
        payload["columns"] = columns
    return await _call("PUT", f"/api/rulesets/{ruleset_id}", json=payload)


@mcp.tool()
async def delete_ruleset(ruleset_id: str) -> dict:
    """Delete a Custom Ruleset."""
    return await _call("DELETE", f"/api/rulesets/{ruleset_id}")


# ============================================================================================
# Workflows -- named run configurations tied to a (Connector, Custom Ruleset) pair. At most one
# workflow per connector is ever "active" (bookkeeping only -- this demo has no masking-workflow
# execution engine).
# ============================================================================================
@mcp.tool()
async def list_workflows_for_connector(connector_id: str) -> list[dict]:
    """List every Workflow belonging to one Connector."""
    return (await _call("GET", f"/api/connectors/{connector_id}/workflows"))["workflows"]


@mcp.tool()
async def list_all_workflows() -> list[dict]:
    """List every Workflow across every Environment/Connector (each enriched with connectorName,
    environmentId, environmentName)."""
    return (await _call("GET", "/api/workflows"))["workflows"]


@mcp.tool()
async def create_workflow(
    connector_id: str,
    name: str,
    description: Optional[str] = None,
    ruleset_id: Optional[str] = None,
) -> dict:
    """Create a Workflow on a Connector, optionally linking it to one of that connector's Custom
    Rulesets via ruleset_id (must belong to the same connector_id, or the call fails). The first
    Workflow created for a connector becomes active automatically."""
    return await _call("POST", "/api/workflows", json={
        "connectorId": connector_id, "name": name, "description": description, "rulesetId": ruleset_id,
    })


@mcp.tool()
async def update_workflow(
    workflow_id: str,
    connector_id: Optional[str] = None,
    name: Optional[str] = None,
    description: Optional[str] = None,
    ruleset_id: Optional[str] = None,
) -> dict:
    """Update a Workflow. Omit any field to leave it unchanged; pass ruleset_id="" to clear its
    ruleset link."""
    payload: dict[str, Any] = {}
    if connector_id is not None:
        payload["connectorId"] = connector_id
    if name is not None:
        payload["name"] = name
    if description is not None:
        payload["description"] = description
    if ruleset_id is not None:
        payload["rulesetId"] = ruleset_id or None
    return await _call("PUT", f"/api/workflows/{workflow_id}", json=payload)


@mcp.tool()
async def activate_workflow(workflow_id: str) -> list[dict]:
    """Mark one Workflow active, deactivating any other Workflow on the same connector (at most
    one workflow per connector is ever active). Returns that connector's updated workflow list."""
    return (await _call("POST", f"/api/workflows/{workflow_id}/activate"))["workflows"]


@mcp.tool()
async def delete_workflow(workflow_id: str) -> dict:
    """Delete a Workflow."""
    return await _call("DELETE", f"/api/workflows/{workflow_id}")


# ============================================================================================
# Algorithms & tokenization test calls
# ============================================================================================
@mcp.tool()
async def list_algorithms() -> list[dict]:
    """List every masking/tokenization algorithm this demo knows about (framework, algorithm_name,
    and the SQL UDF that runs it directly against Postgres, if one exists)."""
    return (await _call("GET", "/api/algorithms"))["algorithms"]


@mcp.tool()
async def tokenize_values(values: list[str]) -> dict:
    """Tokenize a batch of plaintext values via the real tokenization-api (reversible). Returns
    {"results": [...], "failureCount": N, ...}; a null in `values` stays null in the results."""
    return await _call("POST", "/api/tokenize", json={"values": values})


@mcp.tool()
async def reidentify_values(values: list[str]) -> dict:
    """Reidentify a batch of previously-tokenized values back to their original plaintext, via the
    real tokenization-api. Returns {"results": [...], "failureCount": N, ...}."""
    return await _call("POST", "/api/reidentify", json={"values": values})


# ============================================================================================
# SQL
# ============================================================================================
@dataclass
class DatabasePassword:
    password: str


@mcp.tool()
async def connect_database(
    ctx: Context,
    host: str = "localhost",
    port: str = "5432",
    database: str = "dynamicmasking",
    user: str = "dynamicmasking",
) -> dict:
    """Connect to the local demo Postgres database (needed before run_sql_query()). Prompts for the
    password via a dialog rather than accepting it as a tool argument, so it never appears in the
    conversation transcript or MCP logs -- even though this is normally just the local demo's own
    default credentials, not a real secret."""
    result = await ctx.elicit("Enter the Postgres password to connect", response_type=DatabasePassword)
    if result.action != "accept":
        raise ToolError("Database connect cancelled -- no password provided.")
    await _call("POST", "/api/db/connect", json={
        "host": host, "port": port, "database": database, "user": user, "password": result.data.password,
    })
    return {"connected": True, "host": host, "port": port, "database": database, "user": user}


@mcp.tool()
async def run_sql_query(sql: str) -> dict:
    """Run a raw SQL query directly against the local demo Postgres database (via connect_database()
    first). To see masked output, call the demo's own SQL functions in your query text yourself,
    e.g. `SELECT id, mask_email(email) AS email FROM customers` -- this endpoint does no masking on
    its own, unlike run_sql_interception_query(). Returns {"columns": [...], "rows": [[...], ...]}."""
    return await _call("POST", "/api/db/query", json={"sql": sql})


@mcp.tool()
async def run_sql_interception_query(sql: str) -> dict:
    """Run a SQL query through the real sql-interception-proxy service, which applies the
    SQL Interception environment's configured masking automatically. Returns
    {"columns": [...], "rows": [[...], ...], "maskedColumns": [...]}."""
    return await _call("POST", "/api/sql/query", json={"sql": sql})


# ============================================================================================
# Continuous Compliance Engine integration -- read-only / attach / pull-from-engine ONLY.
# See this file's module docstring: no tool here may send a mutating (PUT/DELETE/PATCH) request
# to the real attached engine, and none should be added without deliberate sign-off.
# ============================================================================================
@dataclass
class EngineCredentials:
    username: str
    password: str


@mcp.tool()
async def attach_engine(ctx: Context, host: str) -> dict:
    """Attach to a Delphix Continuous Compliance Engine at `host` (bare hostname or full URL, both
    tolerated). Prompts for username/password via a dialog rather than accepting them as tool
    arguments, so the password never appears in the conversation transcript or MCP logs. This only
    logs in and holds a session -- it never modifies anything on the engine."""
    result = await ctx.elicit(f"Enter credentials for the Delphix Engine at {host}", response_type=EngineCredentials)
    if result.action != "accept":
        raise ToolError("Attach cancelled -- no credentials provided.")
    return await _call("POST", "/api/engine/attach", json={
        "host": host, "username": result.data.username, "password": result.data.password,
    })


@mcp.tool()
async def get_engine_attach_status() -> dict:
    """Check whether this demo is currently attached to a Delphix Engine, and to which host/user."""
    return await _call("GET", "/api/engine/attach-status")


@mcp.tool()
async def list_engine_rulesets() -> list[dict]:
    """List the database rulesets on the currently-attached Delphix Engine (read-only; call
    attach_engine() first). Best-effort -- the real engine's exact response shape hasn't been
    verified against every engine version."""
    return (await _call("GET", "/api/engine/database-rulesets"))["rulesets"]


@mcp.tool()
async def export_engine_ruleset(ruleset_id: str) -> dict:
    """Fetch one database ruleset's full detail from the currently-attached Delphix Engine
    (read-only export; call attach_engine() first)."""
    return await _call("GET", f"/api/engine/database-rulesets/{ruleset_id}/export")


@mcp.tool()
async def sync_engine_key() -> dict:
    """Read the currently-attached Delphix Engine's configured data encryption key and write it
    into this local demo's own .env (rebuilding tokenization-api afterward) -- pulls from the
    engine into the demo, never pushes anything to the engine. Only works against a local
    docker-compose deployment of this demo, and requires attach_engine() first."""
    return await _call("POST", "/api/engine/sync-key")


# ============================================================================================
# Status / crypto config
# ============================================================================================
@mcp.tool()
async def get_demo_status() -> dict:
    """Get this demo's current tokenization-api target, crypto config, and reachability status."""
    return await _call("GET", "/api/status")


@dataclass
class PlaintextKey:
    data_encryption_key_base64: str


@dataclass
class KmsCredentials:
    data_encryption_key_ciphertext_base64: str
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_session_token: str = ""


@mcp.tool()
async def configure_crypto(
    ctx: Context,
    crypto_provider: str = "BCFIPS",
    cipher_algorithm: str = "AES-CBC-CTS",
    key_source: str = "PLAINTEXT",
    kms_key_id: Optional[str] = None,
    aws_region: Optional[str] = None,
) -> dict:
    """Reconfigure this demo's local tokenization-api crypto settings (only works against a local
    docker-compose deployment -- rebuilds the tokenization-api container). key_source must be
    "PLAINTEXT" or "KMS". The actual key material (a plaintext AES key, or a KMS ciphertext blob +
    optional AWS credentials) is collected via a dialog, never as a tool argument, so it never
    appears in the conversation transcript or MCP logs."""
    key_source = key_source.upper()
    payload: dict[str, Any] = {
        "cryptoProvider": crypto_provider, "cipherAlgorithm": cipher_algorithm, "keySource": key_source,
    }
    if key_source == "PLAINTEXT":
        result = await ctx.elicit("Enter the Base64 AES data encryption key", response_type=PlaintextKey)
        if result.action != "accept":
            raise ToolError("Configure cancelled -- no key provided.")
        payload["dataEncryptionKeyBase64"] = result.data.data_encryption_key_base64
    elif key_source == "KMS":
        result = await ctx.elicit("Enter the KMS-wrapped key ciphertext (and AWS credentials, if needed)", response_type=KmsCredentials)
        if result.action != "accept":
            raise ToolError("Configure cancelled -- no key material provided.")
        payload["dataEncryptionKeyCiphertextBase64"] = result.data.data_encryption_key_ciphertext_base64
        payload["awsAccessKeyId"] = result.data.aws_access_key_id
        payload["awsSecretAccessKey"] = result.data.aws_secret_access_key
        payload["awsSessionToken"] = result.data.aws_session_token
        payload["kmsKeyId"] = kms_key_id or ""
        payload["awsRegion"] = aws_region or ""
    else:
        raise ToolError('key_source must be "PLAINTEXT" or "KMS"')
    return await _call("POST", "/api/configure", json=payload)


if __name__ == "__main__":
    mcp.run(transport="stdio")
