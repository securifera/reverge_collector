"""CLI: serialize scan objects into the Reverge scan-import envelope.

Build scan records — hosts, ports, domains, services, components, vulns, HTTP
endpoints, certificates, credentials — with the native
:mod:`reverge_collector.data_model` serializers and emit the
``{scan_id, tool_id, obj_list}`` payload that the Reverge server's
``import_scan_data`` tool consumes. Clone this project and run the CLI to turn a
finding into that blob, then hand the blob to ``import_scan_data`` — no collector
session/credentials required.

Two input modes:

**Flags** — describe one object graph on the command line. Dependencies are
enforced and parents wired automatically (a port needs a host; a component,
vuln, certificate or endpoint needs a port, which needs a host)::

    python -m reverge_collector.scan_import_cli --scan-id <hex> \\
        --host 1.2.3.4 --port 80 --component Apache --version 1.0 \\
        --url https://www.example.com

A ``--url`` contributes a domain (its hostname) and an endpoint (its path); when
no ``--port`` is given it also derives the port and TLS flag from the URL.

**Document** — a flat JSON records list (``--in`` / stdin) for building many
objects at once; see ``build_envelope_from_doc``::

    cat findings.json | python -m reverge_collector.scan_import_cli

Output goes to stdout or ``--out``; feed it to ``import_scan_data``.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import sys
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from reverge_collector import data_model

# Protocol names -> stored proto int (Port.proto: TCP 0, UDP 1).
_PROTO_MAP: Dict[Any, int] = {'tcp': 0, 'udp': 1, 6: 0, 17: 1, 0: 0, 1: 1}


def _new_tool_id() -> str:
    return format(uuid.uuid4().int, 'x')


def _sha1_hex(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest()


def _is_ip(value: Optional[str]) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Document mode: flat records list -> envelope
# ---------------------------------------------------------------------------

# Record type -> (data_model class, takes parent_id, copied field names).
FIELD_MAP: Dict[str, Dict[str, Any]] = {
    'host': {'cls': data_model.Host, 'parent': False, 'fields': ['ipv4_addr', 'ipv6_addr']},
    'domain': {'cls': data_model.Domain, 'parent': True, 'fields': ['name']},
    'operatingsystem': {
        'cls': data_model.OperatingSystem,
        'parent': True,
        'fields': ['name', 'version'],
    },
    'port': {'cls': data_model.Port, 'parent': True, 'fields': []},
    'cpe': {
        'cls': data_model.Cpe,
        'parent': True,
        'fields': ['vendor', 'product', 'version', 'part'],
    },
    'applicationprotocol': {
        'cls': data_model.ApplicationProtocol,
        'parent': True,
        'fields': ['name', 'description'],
    },
    'vuln': {
        'cls': data_model.Vuln,
        'parent': True,
        'fields': ['name', 'vuln_details', 'endpoint_id'],
    },
    'listitem': {'cls': data_model.ListItem, 'parent': False, 'fields': []},
    'screenshot': {
        'cls': data_model.Screenshot,
        'parent': False,
        'fields': ['screenshot', 'image_hash'],
    },
    'httpendpoint': {'cls': data_model.HttpEndpoint, 'parent': True, 'fields': ['web_path_id']},
    'httpendpointdata': {
        'cls': data_model.HttpEndpointData,
        'parent': True,
        'fields': [
            'title',
            'status',
            'domain_id',
            'screenshot_id',
            'last_modified',
            'fav_icon_hash',
            'content_length',
        ],
    },
    'certificate': {
        'cls': data_model.Certificate,
        'parent': True,
        'fields': ['issuer', 'issued', 'expires', 'fingerprint_hash'],
    },
    'credential': {
        'cls': data_model.Credential,
        'parent': False,
        'fields': ['username', 'password', 'privileged'],
    },
}


def _coerce_proto(value: Any) -> int:
    key = value.strip().lower() if isinstance(value, str) else value
    if key not in _PROTO_MAP:
        raise ValueError(f'Invalid proto {value!r}; expected tcp/udp (or 6/17, 0/1).')
    return _PROTO_MAP[key]


def build_records_from_doc(records_spec: List[Dict[str, Any]]) -> List[Any]:
    """Build data_model records from a flat spec, resolving ref/parent links.

    Records are processed in order; a ``parent`` must reference the ``ref`` of an
    earlier record.
    """
    if not isinstance(records_spec, list):
        raise ValueError("'records' must be a list.")

    ref_to_id: Dict[str, str] = {}
    built: List[Any] = []

    for spec in records_spec:
        if not isinstance(spec, dict) or 'type' not in spec:
            raise ValueError("Each record needs a 'type'.")
        rtype = spec['type']
        meta = FIELD_MAP.get(rtype)
        if meta is None:
            raise ValueError(f'Unknown record type: {rtype!r}')

        parent_id = None
        if spec.get('parent') is not None:
            parent_ref = spec['parent']
            if parent_ref not in ref_to_id:
                raise ValueError(f'Unknown parent ref {parent_ref!r} for {rtype} record.')
            parent_id = ref_to_id[parent_ref]

        rec = meta['cls'](parent_id=parent_id) if meta['parent'] else meta['cls']()

        for field in meta['fields']:
            if field in spec and spec[field] is not None:
                setattr(rec, field, spec[field])

        if rtype == 'port':
            if spec.get('port') is not None:
                rec.port = str(spec['port'])
            if spec.get('proto') is not None:
                rec.proto = _coerce_proto(spec['proto'])
            rec.secure = bool(spec.get('secure', False))
        elif rtype == 'listitem':
            if spec.get('web_path') is not None:
                rec.web_path = spec['web_path']
                rec.web_path_hash = _sha1_hex(rec.web_path)
        elif rtype == 'httpendpoint' and spec.get('web_path') is not None:
            listitem = data_model.ListItem()
            listitem.web_path = spec['web_path']
            listitem.web_path_hash = _sha1_hex(listitem.web_path)
            built.append(listitem)
            rec.web_path_id = listitem.id

        if spec.get('ref') is not None:
            ref_to_id[spec['ref']] = rec.id
        built.append(rec)

    return built


def build_envelope_from_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Build the import_scan_data envelope from a findings document."""
    if not isinstance(doc, dict) or 'scan_id' not in doc:
        raise ValueError("Document must be an object with a 'scan_id'.")
    records = build_records_from_doc(doc.get('records', []))
    return _envelope(doc['scan_id'], doc.get('tool_id'), records)


# ---------------------------------------------------------------------------
# Flag mode: one object graph from argparse args
# ---------------------------------------------------------------------------


def _parse_url(url: str) -> Dict[str, Any]:
    """Split a URL into scheme/host/port/path/secure, filling scheme defaults."""
    u = urlparse(url if '://' in url else 'http://' + url)
    scheme = (u.scheme or 'http').lower()
    secure = scheme == 'https'
    host = u.hostname
    port = u.port or (443 if secure else 80)
    path = u.path or '/'
    return {
        'scheme': scheme,
        'secure': secure,
        'host': host,
        'port': port,
        'path': path,
        'is_ip': _is_ip(host),
    }


def _make_host(host_ip: str) -> Any:
    host = data_model.Host()
    if ':' in host_ip:
        host.ipv6_addr = host_ip
    else:
        host.ipv4_addr = host_ip
    return host


def build_records_from_args(args: argparse.Namespace) -> List[Any]:
    """Build one object graph from parsed CLI flags, enforcing dependencies.

    Raises ValueError (surfaced as a CLI error) when a dependency is missing —
    e.g. a component without a port, or a port without a host.
    """
    url_info = _parse_url(args.url) if args.url else None

    # A credential is the only standalone object; everything else hangs off a host.
    wants_host = any(
        [
            args.host,
            args.domain,
            args.os,
            args.port,
            args.component,
            args.vuln,
            args.url,
            args.path,
            args.cert_issuer,
            args.cert_fingerprint,
        ]
    )

    host_ip = args.host
    if not host_ip and url_info and url_info['is_ip']:
        host_ip = url_info['host']

    records: List[Any] = []

    host_obj = None
    if wants_host:
        if not host_ip:
            raise ValueError('a host is required — pass --host <ip> (or a --url with an IP host).')
        host_obj = _make_host(host_ip)
        records.append(host_obj)

    # Domains: explicit --domain plus the URL hostname (when it's a name, not IP).
    domain_by_name: Dict[str, Any] = {}
    for name in args.domain or []:
        dom = data_model.Domain(parent_id=host_obj.id)
        dom.name = name
        records.append(dom)
        domain_by_name[name] = dom

    url_domain_obj = None
    if url_info and url_info['host'] and not url_info['is_ip']:
        name = url_info['host']
        url_domain_obj = domain_by_name.get(name)
        if url_domain_obj is None:
            url_domain_obj = data_model.Domain(parent_id=host_obj.id)
            url_domain_obj.name = name
            records.append(url_domain_obj)
            domain_by_name[name] = url_domain_obj

    if args.os:
        os_obj = data_model.OperatingSystem(parent_id=host_obj.id)
        os_obj.name = args.os
        if args.os_version:
            os_obj.version = args.os_version
        records.append(os_obj)

    # The working port: explicit --port, else derived from --url.
    port_obj = None
    if args.port is not None:
        port_obj = data_model.Port(parent_id=host_obj.id)
        port_obj.port = str(args.port)
        port_obj.proto = _coerce_proto(args.proto)
        port_obj.secure = bool(args.secure)
        records.append(port_obj)
    elif url_info:
        port_obj = data_model.Port(parent_id=host_obj.id)
        port_obj.port = str(url_info['port'])
        port_obj.proto = 0
        port_obj.secure = url_info['secure']
        records.append(port_obj)

    if args.component:
        if port_obj is None:
            raise ValueError('--component requires a port — pass --port (or a --url with a port).')
        comp = data_model.Cpe(parent_id=port_obj.id)
        comp.product = args.component
        if args.vendor:
            comp.vendor = args.vendor
        if args.version:
            comp.version = args.version
        comp.part = args.part or 'a'
        records.append(comp)

    if args.vuln:
        if port_obj is None:
            raise ValueError('--vuln requires a port — pass --port (or a --url with a port).')
        vuln = data_model.Vuln(parent_id=port_obj.id)
        vuln.name = args.vuln
        if args.vuln_details:
            vuln.vuln_details = args.vuln_details
        records.append(vuln)

    if args.cert_issuer or args.cert_fingerprint:
        if port_obj is None:
            raise ValueError('--cert-* requires a port — pass --port (or a --url with a port).')
        cert = data_model.Certificate(parent_id=port_obj.id)
        cert.issuer = args.cert_issuer
        cert.fingerprint_hash = args.cert_fingerprint
        if args.cert_issued is not None:
            cert.issued = args.cert_issued
        if args.cert_expires is not None:
            cert.expires = args.cert_expires
        records.append(cert)

    if args.url or args.path:
        if port_obj is None:
            raise ValueError('--url/--path requires a port — pass --port or a --url with a port.')
        path = args.path or (url_info['path'] if url_info else None) or '/'
        listitem = data_model.ListItem()
        listitem.web_path = path
        listitem.web_path_hash = _sha1_hex(path)
        records.append(listitem)

        endpoint = data_model.HttpEndpoint(parent_id=port_obj.id)
        endpoint.web_path_id = listitem.id
        records.append(endpoint)

        if args.title is not None or args.status is not None or args.content_length is not None:
            data = data_model.HttpEndpointData(parent_id=endpoint.id)
            data.title = args.title
            if args.status is not None:
                data.status = args.status
            if args.content_length is not None:
                data.content_length = args.content_length
            if url_domain_obj is not None:
                data.domain_id = url_domain_obj.id
            records.append(data)

    if args.username:
        cred = data_model.Credential()
        cred.username = args.username
        cred.password = args.password or ''
        cred.privileged = bool(args.privileged)
        records.append(cred)

    if not records:
        raise ValueError('no objects specified — pass --host and related flags (see --help).')

    return records


# ---------------------------------------------------------------------------
# Shared + entry point
# ---------------------------------------------------------------------------


def _envelope(scan_id: str, tool_id: Optional[str], records: List[Any]) -> Dict[str, Any]:
    return {
        'scan_id': scan_id,
        'tool_id': tool_id or _new_tool_id(),
        'obj_list': [rec.to_jsonable() for rec in records],
    }


def _has_object_flags(args: argparse.Namespace) -> bool:
    return any(
        [
            args.host,
            args.domain,
            args.os,
            args.port is not None,
            args.component,
            args.vuln,
            args.url,
            args.path,
            args.cert_issuer,
            args.cert_fingerprint,
            args.username,
        ]
    )


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='scan_import_cli',
        description='Serialize scan objects into the import_scan_data envelope.',
    )
    p.add_argument('--scan-id', help='Hex id of the scan to import into (required in flag mode)')
    p.add_argument('--tool-id', help='Hex tool id (auto-generated when omitted)')

    host = p.add_argument_group('host')
    host.add_argument('--host', help='Host IPv4/IPv6 address (root of the graph)')
    host.add_argument('--domain', action='append', help='Domain name on the host (repeatable)')
    host.add_argument('--os', help='Operating system name')
    host.add_argument('--os-version', help='Operating system version')

    port = p.add_argument_group('port (requires --host)')
    port.add_argument('--port', help='Port number')
    port.add_argument(
        '--proto', choices=['tcp', 'udp'], default='tcp', help='Protocol (default tcp)'
    )
    port.add_argument('--secure', action='store_true', help='Service uses TLS/SSL')

    comp = p.add_argument_group('component / vuln (require a port)')
    comp.add_argument('--component', '--product', dest='component', help='Software product name')
    comp.add_argument('--vendor', help='Component vendor')
    comp.add_argument('--version', help='Component version')
    comp.add_argument('--part', choices=['a', 'o', 'h'], default='a', help='CPE part (default a)')
    comp.add_argument('--vuln', help='Vulnerability name/id (e.g. a CVE)')
    comp.add_argument('--vuln-details', help='Vulnerability details')

    cert = p.add_argument_group('certificate (requires a port)')
    cert.add_argument('--cert-issuer', help='Certificate issuer')
    cert.add_argument('--cert-fingerprint', help='Certificate fingerprint hash')
    cert.add_argument('--cert-issued', type=int, help='Issued epoch seconds')
    cert.add_argument('--cert-expires', type=int, help='Expiry epoch seconds')

    ep = p.add_argument_group('http endpoint (requires a port; --url can supply one)')
    ep.add_argument(
        '--url', help='URL — contributes a domain + endpoint, and a port when none given'
    )
    ep.add_argument('--path', help='Web path for the endpoint (alternative to --url)')
    ep.add_argument('--title', help='HTTP response title')
    ep.add_argument('--status', type=int, help='HTTP status code')
    ep.add_argument('--content-length', dest='content_length', type=int, help='Response length')

    cred = p.add_argument_group('credential (standalone)')
    cred.add_argument('--username', help='Credential username')
    cred.add_argument('--password', help='Credential password')
    cred.add_argument('--privileged', action='store_true', help='Credential is privileged')

    io_grp = p.add_argument_group('input / output')
    io_grp.add_argument(
        '--in', dest='infile', help='Read a findings document (JSON) instead of flags'
    )
    io_grp.add_argument('--out', dest='outfile', help='Write envelope here (default: stdout)')
    io_grp.add_argument('--indent', type=int, default=None, help='Pretty-print indent')
    return p


def _build_envelope(args: argparse.Namespace, parser: argparse.ArgumentParser) -> Dict[str, Any]:
    if args.infile:
        with open(args.infile) as f:
            return build_envelope_from_doc(json.loads(f.read()))

    if _has_object_flags(args):
        if not args.scan_id:
            parser.error('--scan-id is required when adding objects via flags')
        try:
            records = build_records_from_args(args)
        except ValueError as exc:
            parser.error(str(exc))
        return _envelope(args.scan_id, args.tool_id, records)

    # No file, no object flags: read a findings document from stdin.
    return build_envelope_from_doc(json.loads(sys.stdin.read()))


def build_envelope_from_argv(argv: List[str]) -> Dict[str, Any]:
    """Parse ``argv`` and return the import envelope (used by tests and main)."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    return _build_envelope(args, parser)


def main(argv: List[str] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    envelope = _build_envelope(args, parser)
    out = json.dumps(envelope, indent=args.indent)

    if args.outfile:
        with open(args.outfile, 'w') as f:
            f.write(out)
    else:
        sys.stdout.write(out)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
