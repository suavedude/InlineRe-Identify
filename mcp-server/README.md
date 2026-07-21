# DynamicMasking MCP server

An MCP server that lets any MCP-capable chat client (Claude Desktop, Claude Code, etc.) drive the
DynamicMasking demo conversationally — Environments, Connectors, Custom Rulesets, Workflows,
Algorithms, SQL/tokenization test calls, and the Continuous Compliance Engine integration.

It's a thin HTTP client: every tool calls one of `demo/server.py`'s existing REST endpoints. It
makes no changes to `demo/server.py` — the two processes just run side by side.

**Two rules this server follows, on purpose:**
- **No destructive calls toward the attached (real) Delphix engine.** Every engine tool is
  read-only, attach (login), or pull-from-engine — never a write/delete/rename against the engine
  itself. See the "Continuous Compliance Engine integration" section in `mcp_server.py` for the
  full reasoning.
- **Real secrets never travel as plain tool arguments.** `attach_engine`, `connect_database`, and
  `configure_crypto` collect passwords/keys via an interactive dialog (MCP *elicitation*), not as
  arguments the model would see or that would sit in a tool-call log.

## Prerequisites

- The demo backend must be running: `python3 demo/server.py` (default `http://localhost:4041`).
- Your MCP client must support **elicitation** for the credential-collecting tools above to work
  (`attach_engine`, `connect_database`, `configure_crypto`). Every other tool works regardless.

## Setup

```bash
cd mcp-server
pip install -r requirements.txt
```

## Configuring which demo backend to talk to

Resolved in this order at server startup:
1. `mcp_config.json` in this directory (written by the demo app's Settings > General > "MCP
   Server" panel) — `{"demoApiBase": "http://your-host:4041"}`.
2. the `DEMO_API_BASE` environment variable.
3. the default, `http://localhost:4041`.

Changing it only takes effect the next time this MCP server process is (re)started.

## Registering with an MCP client

**Claude Code:**
```bash
claude mcp add dynamicmasking -- python3 /absolute/path/to/mcp-server/mcp_server.py
```

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "dynamicmasking": {
      "command": "python3",
      "args": ["/absolute/path/to/mcp-server/mcp_server.py"]
    }
  }
}
```

Then, in a fresh conversation, try something like "list my environments" or "create a new
Tokenization environment called Demo Env".

## Running it standalone (for testing)

```bash
python3 mcp_server.py
```

This starts the server over stdio, same as an MCP client would launch it. To call tools without any
chat client, use FastMCP's own in-process test client:

```python
import asyncio
from fastmcp import Client
import mcp_server as m

async def main():
    async with Client(m.mcp) as client:
        result = await client.call_tool("list_environments", {})
        print(result.data)

asyncio.run(main())
```
