#!/usr/bin/env python3
"""
Local demo backend for the InlineRe-Identify tokenization API.

Serves demo/index.html and two kinds of endpoints, stdlib-only (no pip install needed):

  GET  /api/status      -> currently configured crypto provider/algorithm/key source (from
                            .env) plus whether tokenization-api is answering /healthz.
  POST /api/configure    -> writes the submitted crypto provider/algorithm/key-source fields into
                            .env, then runs `docker compose up -d --build tokenization-api` so the
                            container picks up the new env vars, and polls /healthz until it's up.
  POST /api/tokenize     -> proxies to tokenization-api's /v1/tokenize (server-side, so the
  POST /api/reidentify      browser never needs cross-origin access to the target port).

Requires the docker-compose stack's images to have been built at least once already (see
README.md's "Running locally with Docker + Postgres" section) -- this script only
reconfigures/rebuilds the tokenization-api service, it doesn't run `./gradlew` itself.

By default targets the local docker-compose stack (http://localhost:4051). Override with
TOKENIZATION_API_BASE to point at a remote deployment (e.g. the EC2 setup in deploy/ec2/) for
the tokenize/reidentify panel -- in that case /api/configure is disabled, since it works by
running `docker compose` on this machine, which has no effect on a remote target.
"""
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = REPO_ROOT / ".env"
DEMO_DIR = Path(__file__).resolve().parent
TOKENIZATION_API_BASE = os.environ.get("TOKENIZATION_API_BASE", "http://localhost:4051")
IS_LOCAL_TARGET = "localhost" in TOKENIZATION_API_BASE or "127.0.0.1" in TOKENIZATION_API_BASE
DEMO_PORT = int(os.environ.get("DEMO_PORT", "4041"))

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


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, status, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path, content_type):
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send_file(DEMO_DIR / "index.html", "text/html; charset=utf-8")
            return
        if self.path == "/api/status":
            env = read_env()
            status = {
                "tokenizationApiBase": TOKENIZATION_API_BASE,
                "isLocalTarget": IS_LOCAL_TARGET,
                # These reflect this machine's .env, which only describes reality when the
                # target is local -- against a remote deployment they're not meaningful (the
                # remote instance's own env file is the source of truth there instead).
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
            self._send_json(200, status)
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw_body = self.rfile.read(length) if length else b"{}"

        if self.path == "/api/configure":
            try:
                apply_configuration(json.loads(raw_body))
                self._send_json(200, {"success": True})
            except subprocess.CalledProcessError as e:
                self._send_json(500, {"success": False, "error": e.stderr or str(e)})
            except Exception as e:  # noqa: BLE001 -- surfaced to the UI as the error message
                self._send_json(400, {"success": False, "error": str(e)})
            return

        if self.path in ("/api/tokenize", "/api/reidentify"):
            target = "/v1/tokenize" if self.path == "/api/tokenize" else "/v1/reidentify"
            try:
                req = urllib.request.Request(
                    TOKENIZATION_API_BASE + target, data=raw_body, method="POST",
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=15) as resp:
                    self._send_json(resp.status, json.loads(resp.read()))
            except urllib.error.HTTPError as e:
                self._send_json(e.code, {"error": e.read().decode("utf-8")})
            except Exception as e:  # noqa: BLE001 -- e.g. connection refused if server is down
                self._send_json(502, {"error": f"tokenization-api unreachable: {e}"})
            return

        self._send_json(404, {"error": "not found"})


if __name__ == "__main__":
    httpd = HTTPServer(("0.0.0.0", DEMO_PORT), Handler)
    print(f"Demo UI on http://localhost:{DEMO_PORT}")
    httpd.serve_forever()
