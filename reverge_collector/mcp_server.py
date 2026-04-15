#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Collector MCP Server
=====================
Standalone FastMCP server designed to run on a Reverge collector machine.
Exposes tools for the Goose AI agent to interact with the collector:
execute shell commands, read/write files, and list directories.

Isolation model
---------------
* The server binds to a **loopback TCP port** (default 127.0.0.1:17890)
  so it is never reachable from outside the collector host.
* The Reverge server connects to it via an SSH local port forward:

    SSH option added by ExtenderManager:
        -L 127.0.0.1:<local_port>:127.0.0.1:17890

  GooseBot then sends requests to http://127.0.0.1:<local_port>/mcp.
* Loopback-only binding prevents other network hosts from reaching the service.
  Bearer token authentication guards against other local processes.

Authentication
--------------
Every request must carry the collector's API key as a bearer token:

    Authorization: Bearer <api_key>

The collector's API key is written to ``/root/.collector_api_key`` at setup
time (by the Docker build arg or Terraform provisioner).  The MCP server reads
it on startup — no extra credential material is introduced and no SSH write
step is required.

The expected token is loaded from (in priority order):
  1. Environment variable  COLLECTOR_MCP_TOKEN
  2. File path in          COLLECTOR_MCP_TOKEN_FILE  (default /root/.collector_api_key)

Usage (on the collector):
    python3 collector_mcp_server.py

    # Custom port / token file:
    COLLECTOR_MCP_PORT=17890 \\
    COLLECTOR_MCP_TOKEN_FILE=/tmp/.reverge_mcp_token \\
    python3 collector_mcp_server.py

Requirements (collector-side):
    pip install mcp uvicorn
"""

import asyncio
import hmac
import json
import logging
import os
from typing import Any, Dict, Optional

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [collector-mcp] %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("collector.mcp_server")

# ---------------------------------------------------------------------------
# Token — loaded once at startup from env var or token file
# ---------------------------------------------------------------------------


def _load_expected_token() -> str:
    """Return the expected bearer token, or empty string if none is configured."""
    token = os.environ.get("COLLECTOR_MCP_TOKEN", "").strip()
    if token:
        return token
    token_file = os.environ.get(
        "COLLECTOR_MCP_TOKEN_FILE", "/root/.collector_api_key"
    )
    try:
        with open(token_file) as fh:
            return fh.read().strip()
    except OSError:
        return ""


_EXPECTED_TOKEN: str = _load_expected_token()

# ---------------------------------------------------------------------------
# FastMCP server definition
# ---------------------------------------------------------------------------
from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP(
    name="collector-ops",
    instructions=(
        "Tools for interacting with the remote collector system. "
        "Use these tools to run shell commands, read and write files, "
        "and explore the collector's filesystem."
    ),
    stateless_http=True,
)

# Cap on command / file output returned to the AI agent (64 KB).
_MAX_OUTPUT = 65536


# ---------------------------------------------------------------------------
# Token auth ASGI middleware
# ---------------------------------------------------------------------------

class _TokenAuthMiddleware:
    """Validate the per-collector bearer token on every HTTP/WebSocket request."""

    def __init__(self, app):
        self._app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            path = scope.get("path", "?")
            client = scope.get("client", ("unix", 0))
            logger.debug("MCP %s request: %s from %s",
                         scope["type"].upper(), path, client)

            if not _EXPECTED_TOKEN:
                # No token configured — deny all requests to be safe.
                logger.warning(
                    "MCP request rejected: no token configured "
                    "(set COLLECTOR_MCP_TOKEN or COLLECTOR_MCP_TOKEN_FILE)"
                )
                await _send_401(send)
                return

            headers = dict(scope.get("headers", []))
            auth_bytes = headers.get(b"authorization", b"")
            auth_str = auth_bytes.decode("utf-8", errors="replace")
            token = ""
            if auth_str.lower().startswith("bearer "):
                token = auth_str[7:].strip()

            if not token:
                logger.warning(
                    "MCP request rejected: no Authorization header on %s", path)
                await _send_401(send)
                return

            # Constant-time comparison prevents timing side-channels.
            if not hmac.compare_digest(token, _EXPECTED_TOKEN):
                logger.warning(
                    "MCP request rejected: token mismatch on %s "
                    "(got prefix %.8s... expected prefix %.8s...)",
                    path, token, _EXPECTED_TOKEN,
                )
                await _send_401(send)
                return

            logger.debug("MCP request authorised: %s", path)

        await self._app(scope, receive, send)


async def _send_401(send):
    await send({
        "type": "http.response.start",
        "status": 401,
        "headers": [
            (b"content-type", b"application/json"),
            (b"www-authenticate", b'Bearer realm="collector-mcp"'),
        ],
    })
    await send({
        "type": "http.response.body",
        "body": b'{"error":"unauthorized"}',
    })


# ---------------------------------------------------------------------------
# Shell execution tool
# ---------------------------------------------------------------------------

@mcp.tool()
async def shell(command: str) -> str:
    """Execute a shell command on the collector and return its output (stdout + stderr combined)."""
    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return "[ERROR] command timed out after 60 seconds"

        output = stdout.decode("utf-8", errors="replace")
        if len(output) > _MAX_OUTPUT:
            output = output[:_MAX_OUTPUT] + "\n[output truncated]"

        rc = proc.returncode
        if rc != 0:
            return f"[exit {rc}]\n{output}" if output else f"[exit {rc}]"
        return output or "(no output)"
    except Exception as exc:
        return f"[ERROR] {exc}"


# ---------------------------------------------------------------------------
# Filesystem tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def read_file(path: str) -> str:
    """Read and return the text contents of a file on the collector."""
    try:
        def _read():
            with open(path, "r", errors="replace") as fh:
                return fh.read(_MAX_OUTPUT)
        content = await asyncio.to_thread(_read)
        return content or "(empty file)"
    except FileNotFoundError:
        return f"[ERROR] file not found: {path}"
    except PermissionError:
        return f"[ERROR] permission denied: {path}"
    except Exception as exc:
        return f"[ERROR] {exc}"


@mcp.tool()
async def write_file(path: str, content: str) -> str:
    """Write text content to a file on the collector, creating parent directories if needed."""
    try:
        def _write():
            parent = os.path.dirname(os.path.abspath(path))
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(path, "w") as fh:
                fh.write(content)
        await asyncio.to_thread(_write)
        return f"wrote {len(content)} bytes to {path}"
    except PermissionError:
        return f"[ERROR] permission denied: {path}"
    except Exception as exc:
        return f"[ERROR] {exc}"


@mcp.tool()
async def list_directory(path: str = ".") -> str:
    """List the contents of a directory on the collector."""
    try:
        def _list():
            entries = []
            for entry in sorted(os.scandir(path), key=lambda e: (e.is_file(), e.name)):
                kind = "[d]" if entry.is_dir() else "[f]"
                try:
                    size = f"  ({entry.stat().st_size} bytes)" if entry.is_file(
                    ) else ""
                except OSError:
                    size = ""
                entries.append(f"{kind} {entry.name}{size}")
            return "\n".join(entries) if entries else "(empty directory)"
        return await asyncio.to_thread(_list)
    except FileNotFoundError:
        return f"[ERROR] directory not found: {path}"
    except PermissionError:
        return f"[ERROR] permission denied: {path}"
    except Exception as exc:
        return f"[ERROR] {exc}"


# ---------------------------------------------------------------------------
# Optional Reverge API integration
# ---------------------------------------------------------------------------
try:
    import requests as _requests
    from reverge_collector import tool_utils as _tool_utils

    _COLLECTOR_AVAILABLE = True
except ImportError as _import_err:
    _COLLECTOR_AVAILABLE = False
    _import_err_msg = str(_import_err)


# ---------------------------------------------------------------------------
# MCP tool: import_to_reverge
# ---------------------------------------------------------------------------

@mcp.tool()
async def import_to_reverge(
    tool_name: str,
    output_file_path: str,
    scan_id: str,
    tool_id: str,
    reverge_url: str = "",
    reverge_token: str = "",
) -> str:
    """Parse a scan tool output file and import the results into the Reverge database.

    Selects the correct parser based on *tool_name*, then authenticates with
    the Reverge management server (RSA/AES key exchange) and POSTs the
    encrypted records to ``/api/data/import``.

    Typical workflow:
    1. Use the ``shell`` tool to run a scan and write its output to a file.
    2. Call this tool with that file path to push the parsed results to Reverge.

    Supported tool names: ``nmap``

    Args:
        tool_name:        Name of the scan tool that produced the output file.
                          Determines which parser is used (e.g. ``"nmap"``).
        output_file_path: Absolute path to the scan output file on disk.
        scan_id:          Reverge scan ID to associate the results with.
        tool_id:          Reverge tool ID that produced the results.
        reverge_url:      Base URL of the Reverge management server.  Defaults
                          to the ``REVERGE_MANAGER_URL`` environment variable.
        reverge_token:    API bearer token for the Reverge server.  Defaults to
                          the ``REVERGE_API_TOKEN`` environment variable.
    """
    if not _COLLECTOR_AVAILABLE:
        return json.dumps(
            {"error": "reverge_collector integration not available: " + _import_err_msg}
        )

    # ---------------------------------------------------------------------------
    # Parser dispatch
    # ---------------------------------------------------------------------------
    _PARSERS = {
        "nmap": _tool_utils.parse_nmap_xml_to_jsonable,
        "masscan": _tool_utils.parse_masscan_xml_to_jsonable,
        "httpx": _tool_utils.parse_httpx_output_to_jsonable,
        "nuclei": _tool_utils.parse_nuclei_output_to_jsonable,
        "shodan": _tool_utils.parse_shodan_output_to_jsonable,
        "feroxbuster": _tool_utils.parse_feroxbuster_output_to_jsonable,
        "subfinder": _tool_utils.parse_subfinder_output_to_jsonable,
        "iis_short": _tool_utils.parse_iis_short_scan_output_to_jsonable,
        "ip_thc": _tool_utils.parse_ip_thc_output_to_jsonable,
        "gau": _tool_utils.parse_gau_output_to_jsonable,
        "crapsecrets": _tool_utils.parse_crapsecrets_output_to_jsonable,
        "webcap": _tool_utils.parse_webcap_output_to_jsonable,
        "netexec": _tool_utils.parse_netexec_output_to_jsonable,
        "python": _tool_utils.parse_python_scan_output_to_jsonable,
    }

    parser = _PARSERS.get(tool_name.lower().strip())
    if parser is None:
        return json.dumps(
            {
                "error": "Unsupported tool_name %r. Supported values: %s"
                % (tool_name, ", ".join(sorted(_PARSERS)))
            }
        )

    url = (reverge_url or os.environ.get(
        "REVERGE_MANAGER_URL", "")).rstrip("/")
    token = reverge_token or os.environ.get("REVERGE_API_TOKEN", "")

    if not url:
        return json.dumps(
            {"error": "reverge_url not provided and REVERGE_MANAGER_URL not set"}
        )
    if not token:
        return json.dumps(
            {"error": "reverge_token not provided and REVERGE_API_TOKEN not set"}
        )

    try:
        obj_list = await asyncio.to_thread(parser, output_file_path)
    except FileNotFoundError:
        return json.dumps({"error": "Output file not found: %s" % output_file_path})
    except Exception as exc:
        logger.exception("import_to_reverge: file parse failed")
        return json.dumps({"error": "Parse error: %s" % exc})

    if not obj_list:
        return json.dumps({"status": "ok", "message": "No records to import", "imported": 0})

    headers: Dict[str, str] = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"
        ),
        "Authorization": "Bearer " + token,
    }

    try:
        session_key = await asyncio.to_thread(
            _tool_utils.get_session_key, url, headers
        )
    except Exception as exc:
        logger.exception("import_to_reverge: session key exchange failed")
        return json.dumps({"error": "Session key exchange failed: %s" % exc})

    payload = json.dumps(
        {"tool_id": tool_id, "scan_id": scan_id, "obj_list": obj_list}
    ).encode()
    b64_enc = await asyncio.to_thread(_tool_utils.encrypt_data, session_key, payload)

    def _post_import():
        return _requests.post(
            "%s/api/data/import" % url,
            headers=headers,
            json={"data": b64_enc},
            verify=False,
            timeout=60,
        )

    try:
        r = await asyncio.to_thread(_post_import)
    except Exception as exc:
        logger.exception("import_to_reverge: HTTP POST failed")
        return json.dumps({"error": "HTTP request failed: %s" % exc})

    if r.status_code != 200:
        return json.dumps(
            {
                "error": "Reverge server returned HTTP %d" % r.status_code,
                "body": r.text[:1024],
            }
        )

    updated_records: Any = []
    if r.content:
        try:
            content = r.json()
            if "data" in content:
                raw = await asyncio.to_thread(
                    _tool_utils.decrypt_data, session_key, content["data"]
                )
                updated_records = json.loads(raw)
        except Exception as exc:
            logger.warning(
                "import_to_reverge: could not decrypt server response: %s", exc
            )

    return json.dumps(
        {
            "status": "ok",
            "imported": len(obj_list),
            "server_response": updated_records,
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Entry point — bind loopback TCP port, then start uvicorn
# ---------------------------------------------------------------------------

_MCP_HOST = "127.0.0.1"
_MCP_PORT = int(os.environ.get("COLLECTOR_MCP_PORT", "17890"))


def main():
    import uvicorn

    inner = mcp.streamable_http_app()
    asgi_app = _TokenAuthMiddleware(inner)

    logger.info("Starting Collector MCP Server on %s:%d", _MCP_HOST, _MCP_PORT)
    if _EXPECTED_TOKEN:
        logger.info("Bearer token authentication: enabled.")
    else:
        logger.error(
            "No bearer token configured — all requests will be rejected. "
            "Set COLLECTOR_MCP_TOKEN or ensure the API key file exists at "
            "COLLECTOR_MCP_TOKEN_FILE (default /root/.collector_api_key)."
        )

    uvicorn.run(
        asgi_app,
        host=_MCP_HOST,
        port=_MCP_PORT,
        log_level="info",
        access_log=True,
    )


if __name__ == "__main__":
    main()
