"""
Tool output parsing utilities for the Waluigi framework.

Provides standalone functions to parse security tool output files and convert
them to Reverge-compatible data-model objects or JSON.  The same logic can
therefore be reused from:

* Luigi import tasks  (pass ``scope_obj`` / ``tool_instance_id`` for full
  ID-correlation with the live scan)
* The MCP server or any other out-of-band consumer  (omit optional args;
  every record receives a fresh UUID)

Functions:
    remove_dups_from_dict:        Deduplicate a list of dicts by JSON value.
    parse_nmap_xml:               Parse one nmap XML file → list of Record objects.
    parse_nmap_xml_to_jsonable:   Convenience wrapper → list of JSON-serialisable dicts.
"""

import base64
import binascii
import json
import logging
import os
import traceback
import zlib
from typing import Any, Dict, List, Optional

import requests
from Cryptodome.Cipher import AES
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA

from waluigi import data_model

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def remove_dups_from_dict(dict_array: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove duplicate dictionaries from a list by comparing JSON representations.

    Args:
        dict_array: List of dictionaries that may contain duplicates.

    Returns:
        List of unique dictionaries.

    Example:
        >>> scripts = [{'id': 'ssl-cert', 'output': 'x'}, {'id': 'ssl-cert', 'output': 'x'}]
        >>> remove_dups_from_dict(scripts)
        [{'id': 'ssl-cert', 'output': 'x'}]
    """
    script_set: set = set()
    for entry in dict_array:
        script_set.add(json.dumps(entry, sort_keys=True))
    return [json.loads(s) for s in script_set]


# ---------------------------------------------------------------------------
# Nmap XML parsing (delegates to nmap_scan module)
# ---------------------------------------------------------------------------

def parse_nmap_xml_to_jsonable(
    xml_path: str,
    scope_obj: Optional[Any] = None,
    tool_instance_id: Optional[str] = None,
    tool_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Parse a single nmap XML file and return JSON-serialisable dicts."""
    from waluigi.nmap_scan import parse_nmap_xml
    records = parse_nmap_xml(xml_path, scope_obj, tool_instance_id, tool_id)
    return [obj.to_jsonable() for obj in records]


# ---------------------------------------------------------------------------
# Reverge session-key and encryption utilities
# ---------------------------------------------------------------------------
# Session key is stored adjacent to the waluigi package root.
_SESSION_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "session"
)


def _load_session_key() -> Optional[bytes]:
    """Return the cached AES session key from disk, or None."""
    session_path = os.path.abspath(_SESSION_FILE)
    if os.path.exists(session_path):
        try:
            with open(session_path) as fh:
                return binascii.unhexlify(fh.read().strip())
        except Exception:
            pass
    return None


def _save_session_key(key: bytes) -> None:
    """Persist the AES session key to disk as a hex string."""
    session_path = os.path.abspath(_SESSION_FILE)
    try:
        fd = os.open(session_path, os.O_CREAT |
                     os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(binascii.hexlify(key).decode())
    except Exception as exc:
        logger.warning("Could not save session key to disk: %s", exc)


def get_session_key(manager_url: str, headers: Dict[str, str]) -> bytes:
    """Return the AES session key for communicating with the Reverge server.

    Loads from the disk cache when available.  Otherwise performs an RSA/AES
    key-exchange with the management server, caches the result, and returns it.

    Args:
        manager_url: Base URL of the Reverge management server
                     (e.g. ``"https://reverge.example.com"``).
        headers:     HTTP request headers, including the bearer token.

    Returns:
        AES session key bytes.

    Raises:
        RuntimeError: If the key exchange fails or the server response is
                      malformed.
    """
    cached = _load_session_key()
    if cached:
        return cached

    key = RSA.generate(2048)
    private_key_der = key.export_key(format="DER")
    public_key_b64 = base64.b64encode(
        key.publickey().export_key(format="DER")
    ).decode()

    r = requests.post(
        "%s/api/session" % manager_url,
        headers=headers,
        json={"data": public_key_b64},
        verify=False,
        timeout=30,
    )
    if r.status_code != 200:
        raise RuntimeError(
            "Reverge session key exchange failed (HTTP %d)" % r.status_code
        )

    ret_json = r.json()
    if "data" not in ret_json:
        raise RuntimeError("Reverge server did not return a session key")

    enc_session_key = base64.b64decode(ret_json["data"])
    rsa_obj = RSA.import_key(private_key_der)
    session_key: bytes = PKCS1_OAEP.new(rsa_obj).decrypt(enc_session_key)
    _save_session_key(session_key)
    return session_key


def encrypt_data(session_key: bytes, data: bytes) -> str:
    """Compress and AES-EAX encrypt *data*; return a base64-encoded packet.

    The packet format is: ``base64(nonce[16] + tag[16] + ciphertext)``.
    Compatible with the server-side decryption in ``ReconManager``.

    Args:
        session_key: AES key bytes (must be a valid AES key length).
        data:        Raw bytes to encrypt.

    Returns:
        Base64-encoded string ready for JSON transport.
    """
    compressed = zlib.compress(data)
    cipher = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(compressed)
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()


def decrypt_data(session_key: bytes, b64_data: str) -> bytes:
    """Decode, AES-EAX decrypt, and decompress a Reverge API response payload.

    Args:
        session_key: AES key bytes used for decryption.
        b64_data:    Base64-encoded encrypted packet from the Reverge server.

    Returns:
        Raw decrypted and decompressed bytes.
    """
    enc_data = base64.b64decode(b64_data)
    nonce, tag, ciphertext = enc_data[:16], enc_data[16:32], enc_data[32:]
    cipher = AES.new(session_key, AES.MODE_EAX, nonce)
    return zlib.decompress(cipher.decrypt_and_verify(ciphertext, tag))


# ---------------------------------------------------------------------------
# Masscan, HTTPX, and Nuclei parsing (delegates to each tool's scan module)
# ---------------------------------------------------------------------------

def parse_masscan_xml_to_jsonable(
    xml_path: str,
    tool_instance_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Parse a Masscan XML output file and return JSON-serialisable dicts."""
    from waluigi.masscan import parse_masscan_xml
    return [obj.to_jsonable() for obj in parse_masscan_xml(xml_path, tool_instance_id)]


def parse_httpx_output_to_jsonable(
    output_file: str,
    tool_instance_id: Optional[str] = None,
    tool_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Parse an httpx JSON output file and return JSON-serialisable dicts."""
    from waluigi.httpx_scan import parse_httpx_output
    return [obj.to_jsonable() for obj in parse_httpx_output(
        [output_file], tool_instance_id, tool_id)]


def parse_nuclei_output_to_jsonable(
    output_file: str,
    tool_instance_id: Optional[str] = None,
    tool_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Parse a Nuclei JSON output file and return JSON-serialisable dicts."""
    from waluigi.nuclei_scan import parse_nuclei_output
    return [obj.to_jsonable() for obj in parse_nuclei_output(
        output_file, None, tool_instance_id, tool_id)]


def parse_shodan_output_to_jsonable(
    output_file: str,
    tool_instance_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Parse a Shodan JSON output file and return JSON-serialisable dicts."""
    from waluigi.shodan_lookup import parse_shodan_output
    return [obj.to_jsonable() for obj in parse_shodan_output(output_file, tool_instance_id)]


def parse_feroxbuster_output_to_jsonable(
    output_file: str,
    tool_instance_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Parse a Feroxbuster JSON metadata output file and return JSON-serialisable dicts."""
    from waluigi.feroxbuster_scan import parse_feroxbuster_output
    return [obj.to_jsonable() for obj in parse_feroxbuster_output(output_file, tool_instance_id)]


def parse_subfinder_output_to_jsonable(
    output_file: str,
    tool_instance_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Parse a Subfinder JSON output file and return JSON-serialisable dicts."""
    from waluigi.subfinder_scan import parse_subfinder_output
    return [obj.to_jsonable() for obj in parse_subfinder_output(output_file, tool_instance_id)]


def parse_iis_short_scan_output_to_jsonable(
    output_file: str,
    tool_instance_id: Optional[str] = None,
    tool_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Parse an IIS Shortname Scanner JSON output file and return JSON-serialisable dicts."""
    from waluigi.iis_short_scan import parse_iis_short_scan_output
    return [obj.to_jsonable() for obj in parse_iis_short_scan_output(output_file, tool_instance_id, tool_id)]


def parse_ip_thc_output_to_jsonable(
    output_file: str,
    tool_instance_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Parse an IP THC JSON output file and return JSON-serialisable dicts."""
    from waluigi.ip_thc_lookup import parse_ip_thc_output
    return [obj.to_jsonable() for obj in parse_ip_thc_output(output_file, tool_instance_id)]


def parse_gau_output_to_jsonable(
    output_file: str,
    tool_instance_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Parse a Gau JSON metadata output file and return JSON-serialisable dicts."""
    from waluigi.gau_scan import parse_gau_output
    return [obj.to_jsonable() for obj in parse_gau_output(output_file, tool_instance_id)]


def parse_crapsecrets_output_to_jsonable(
    output_file: str,
    tool_instance_id: Optional[str] = None,
    tool_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Parse a CrapSecrets JSON output file and return JSON-serialisable dicts."""
    from waluigi.crapsecrets_scan import parse_crapsecrets_output
    return [obj.to_jsonable() for obj in parse_crapsecrets_output(output_file, tool_instance_id, tool_id)]


def parse_webcap_output_to_jsonable(
    output_file: str,
    tool_instance_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Parse a Webcap JSON-lines metadata file and return JSON-serialisable dicts."""
    from waluigi.webcap_scan import parse_webcap_output
    return [obj.to_jsonable() for obj in parse_webcap_output(output_file, tool_instance_id)]


def parse_netexec_output_to_jsonable(
    output_file: str,
    tool_instance_id: Optional[str] = None,
    tool_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Parse a Netexec JSON metadata output file and return JSON-serialisable dicts."""
    from waluigi.netexec_scan import parse_netexec_output
    return [obj.to_jsonable() for obj in parse_netexec_output(output_file, tool_instance_id, tool_id)]


def parse_python_scan_output_to_jsonable(
    output_file: str,
    tool_instance_id: Optional[str] = None,
    tool_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Parse a Python scan output file and return JSON-serialisable dicts."""
    from waluigi.python_scan import parse_python_scan_output
    return [obj.to_jsonable() for obj in parse_python_scan_output(output_file, tool_instance_id, tool_id)]
