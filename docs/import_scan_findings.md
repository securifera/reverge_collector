# Import Scan Findings

## Goal
Turn a finding you determined on your own — while running collector tasks, from
manual analysis, or from an external tool — into Reverge records, without a full
collector import cycle. Example: you're scanning a host and conclude "port 443 is
running PHP 8.1." Build the payload with `scan_import_cli`, then hand it to the
Reverge server's `import_scan_data` MCP tool. `import_scan_data` and the
collector's web import endpoint both funnel into the same backend, so results
land identically.

The CLI ships with this project, so on a collector it's already available as
`python -m reverge_collector.scan_import_cli`.

## Step 1 — Get a scan to import into
Every import attaches to an existing scan (the backend resolves the scan's target
from it). On the Reverge server, call `search_reverge_scans` to find a suitable
`scan_id` (hex) for the target you're working on. Note it for steps 2 and 3.

## Step 2 — Build the envelope with `scan_import_cli`
The CLI builds the records with the native serializers, assigns record ids, wires
parent links, and prints the `{scan_id, tool_id, obj_list}` envelope to stdout
(or `--out FILE`). Two modes.

### Flag mode (one object graph — the common case)
Describe the finding with flags. Dependencies are enforced automatically: a port
needs a host; a component, vuln, certificate, or endpoint needs a port, which
needs a host. The "PHP 8.1 on 443" case:

```bash
python -m reverge_collector.scan_import_cli --scan-id <scan_hex> \
    --host 10.0.0.5 --port 443 --secure --component php --version 8.1
```

An endpoint you just discovered — `--url` contributes a domain (its hostname) and
an endpoint (its path), and derives the port + TLS flag when no `--port` is given:

```bash
python -m reverge_collector.scan_import_cli --scan-id <scan_hex> \
    --host 10.0.0.5 --url https://admin.example.com/dashboard --title Dashboard --status 200
# -> host + domain + port 443 (secure) + /dashboard endpoint + endpoint data
```

Flag reference (run `--help` for everything):

| Object (dependency) | Flags |
| --- | --- |
| host (root) | `--host <ip>` |
| domain (needs host) | `--domain <name>` (repeatable) |
| operating system (needs host) | `--os <name>` `--os-version <v>` |
| port (needs host) | `--port <n>` `--proto tcp\|udp` `--secure` |
| component/CPE (needs port) | `--component <product>` `--vendor <v>` `--version <v>` `--part a\|o\|h` |
| vuln (needs port) | `--vuln <name>` `--vuln-details <text>` |
| certificate (needs port) | `--cert-issuer` `--cert-fingerprint` `--cert-issued` `--cert-expires` |
| http endpoint (needs port) | `--url <url>` and/or `--path <p>` `--title` `--status` `--content-length` |
| credential (standalone) | `--username` `--password` `--privileged` |
| required / output | `--scan-id <hex>` `--tool-id <hex>` `--out <file>` `--indent <n>` |

If a dependency is missing (e.g. `--component` without `--port`), the CLI exits
with an error naming what's needed.

### Document mode (many objects at once)
Write a findings document (flat records with `ref`/`parent` string aliases for
linking) and convert it:

```bash
python -m reverge_collector.scan_import_cli --in findings.json --out envelope.json
# or: cat findings.json | python -m reverge_collector.scan_import_cli
```

`findings.json`:
```json
{
  "scan_id": "<scan_hex>",
  "records": [
    {"type": "host", "ref": "h1", "ipv4_addr": "192.168.1.10"},
    {"type": "domain", "parent": "h1", "name": "api.example.com"},
    {"type": "port", "ref": "p1", "parent": "h1", "port": 443, "proto": "tcp", "secure": true},
    {"type": "cpe", "parent": "p1", "product": "tomcat", "vendor": "apache", "version": "9.0"},
    {"type": "vuln", "parent": "p1", "name": "CVE-2024-1234", "vuln_details": "RCE in handler"},
    {"type": "httpendpoint", "ref": "e1", "parent": "p1", "web_path": "/admin"},
    {"type": "httpendpointdata", "parent": "e1", "title": "Admin", "status": 200}
  ]
}
```

Document-mode record fields (per `type`): host `ipv4_addr`/`ipv6_addr`; domain
`name`; operatingsystem `name`,`version?`; port `port`,`proto`,`secure`; cpe
`product`,`vendor?`,`version?`,`part?`; applicationprotocol `name`; vuln
`name`,`vuln_details?`; httpendpoint `web_path`; httpendpointdata
`title?`,`status?`,`content_length?`; certificate `issuer`,`fingerprint_hash`,
`issued`,`expires`; credential `username`,`password`,`privileged?`.

## Step 3 — Import via the MCP tool
The CLI's stdout is the envelope. Capture it and pass the parsed JSON object as
the `scan_obj` argument to the Reverge `import_scan_data` MCP tool:

```
import_scan_data(scan_obj=<the JSON the CLI printed>)
```

`scan_obj` is the object itself (a dict with `scan_id`/`tool_id`/`obj_list`), not
a string. A success response means the rows were written and mapped to database
ids.

## Rules
- Let the CLI own ids and parent links — never invent record ids, and always give
  a child its parent (a flag's dependency, or a `ref`/`parent` in document mode).
- Only import findings you have evidence for. Do not fabricate hosts/vulns.
