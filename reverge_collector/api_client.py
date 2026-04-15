"""
Reverge API Client Module

Provides ``ApiClient``, a thin transport layer that handles session management,
AES/RSA encryption, and all HTTP interactions with the Reverge management server.
``ReconManager`` delegates every server call through an ``ApiClient`` instance
so that orchestration logic stays free of transport concerns.
"""

import json
import logging
import os
import traceback
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import requests

from reverge_collector import tool_utils

logger = logging.getLogger(__name__)

# Suppress urllib3 SSL warnings globally (targets can have self-signed certs)
requests.packages.urllib3.disable_warnings()

_CUSTOM_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"
)


@dataclass
class ScheduledScanResponse:
    """
    Typed representation of a single entry returned by ``GET /api/scheduler/``.

    Only the fields that ``ScheduledScan.__init__`` accesses are declared here.
    The ``collection_tools`` list is kept as ``SimpleNamespace`` objects because
    it is a deeply-nested hierarchy that is consumed entirely inside
    ``ScheduledScan.__init__`` and benefits from the flexible attribute access
    that ``object_hook`` deserialization provides.

    Attributes:
        id:               Scheduled-scan identifier (server-assigned).
        target_id:        Target scope identifier.
        scan_id:          Scan run identifier.
        collection_tools: List of tool-instance namespaces with ``status``,
                          ``enabled``, ``id``, ``collection_tool`` etc.
    """
    id: str
    target_id: str
    scan_id: str
    collection_tools: List[Any] = field(default_factory=list)


class ApiClient:
    """
    Thin HTTP/encryption client for the Reverge management server.

    Responsibilities:
    - RSA/AES session-key exchange and refresh
    - Transparent encrypt → POST → decrypt for every API call
    - All endpoint methods (one method per server endpoint)

    Attributes:
        manager_url: Base URL of the management server.
        headers:     HTTP headers including the ``Authorization: Bearer`` token.
        session_key: Current AES session key bytes.
        verify_ssl:  Whether to verify TLS certificates (default ``True``;
                     override via ``REVERGE_VERIFY_SSL`` env var).
    """

    def __init__(self, token: str, manager_url: str) -> None:
        self.manager_url = manager_url
        self.headers: Dict[str, str] = {
            "User-Agent": _CUSTOM_USER_AGENT,
            "Authorization": "Bearer " + token,
        }
        self.verify_ssl: bool = os.environ.get(
            "REVERGE_VERIFY_SSL", "true"
        ).lower() in (
            "1", "true", "yes"
        )
        self.session_key: bytes = self._init_session_key()

    # ------------------------------------------------------------------
    # Session helpers
    # ------------------------------------------------------------------

    def _init_session_key(self) -> bytes:
        """Obtain the AES session key, performing the RSA handshake if needed."""
        try:
            # Collector runtime keeps session key in memory only.
            return tool_utils.get_session_key(
                self.manager_url,
                self.headers,
                use_cached=False,
                persist=False,
            )
        except RuntimeError as exc:
            raise RuntimeError(
                "Reverge session key exchange failed: %s" % exc
            ) from exc

    def _refresh_session_key(self) -> bytes:
        """Force a new in-memory session key exchange."""
        self.session_key = self._init_session_key()
        return self.session_key

    # ------------------------------------------------------------------
    # Encrypt / decrypt helpers
    # ------------------------------------------------------------------

    def _encrypt(self, payload: Any) -> str:
        """JSON-encode *payload*, compress, AES-encrypt, return base64 string."""
        json_bytes = json.dumps(payload).encode()
        return tool_utils.encrypt_data(self.session_key, json_bytes)

    def _decrypt(self, content: Dict[str, str]) -> Optional[bytes]:
        """Decrypt a ``{"data": "<b64>"}`` server response; refresh key on failure."""
        if "data" not in content:
            return None
        b64_data = content["data"]
        try:
            return tool_utils.decrypt_data(self.session_key, b64_data)
        except Exception as exc:
            logger.error("Decryption failed: %s — attempting key refresh", exc)
            # Full refresh (memory-only key lifecycle)
            try:
                self._refresh_session_key()
                return tool_utils.decrypt_data(self.session_key, b64_data)
            except Exception as exc2:
                logger.error("Decryption still failed after key refresh: %s", exc2)
                return None

    # ------------------------------------------------------------------
    # Generic encrypted GET / POST wrappers
    # ------------------------------------------------------------------

    def _get(self, path: str, *, as_namespace: bool = False) -> Any:
        """
        Perform a GET request and return the decrypted JSON body.

        Returns ``None`` on 404; raises on other non-200 responses.
        """
        url = "%s%s" % (self.manager_url, path)
        r = requests.get(url, headers=self.headers, verify=self.verify_ssl)
        if r.status_code == 404:
            return None
        if r.status_code != 200:
            logger.error("GET %s returned %d", path, r.status_code)
            return None
        if not r.content:
            return None
        try:
            content = r.json()
            data = self._decrypt(content)
            if data is None:
                return None
            if as_namespace:
                return json.loads(data, object_hook=lambda d: SimpleNamespace(**d))
            return json.loads(data)
        except Exception as exc:
            logger.error("Error parsing GET %s response: %s", path, exc)
            logger.debug(traceback.format_exc())
            return None

    def _post(self, path: str, payload: Any, *,
              expect_response: bool = False, as_namespace: bool = False) -> Any:
        """
        Encrypt *payload*, POST it, optionally decrypt and return the response.

        Returns ``True`` on plain 200 success when ``expect_response=False``.
        Raises ``RuntimeError`` on non-200 responses.
        """
        url = "%s%s" % (self.manager_url, path)
        b64_val = self._encrypt(payload)
        r = requests.post(
            url, headers=self.headers,
            json={"data": b64_val},
            verify=self.verify_ssl,
        )
        if r.status_code == 404:
            return None
        if r.status_code != 200:
            raise RuntimeError("POST %s returned HTTP %d" % (path, r.status_code))
        if not expect_response:
            return True
        if not r.content:
            return None
        try:
            content = r.json()
            data = self._decrypt(content)
            if data is None:
                return None
            if as_namespace:
                return json.loads(data, object_hook=lambda d: SimpleNamespace(**d))
            return json.loads(data)
        except Exception as exc:
            logger.error("Error parsing POST %s response: %s", path, exc)
            logger.debug(traceback.format_exc())
            return None

    # ------------------------------------------------------------------
    # API endpoint methods
    # ------------------------------------------------------------------

    def get_scheduled_scans(self) -> List[ScheduledScanResponse]:
        """Retrieve pending scheduled scans, returning typed ``ScheduledScanResponse`` objects."""
        raw = self._get("/api/scheduler/", as_namespace=True)
        if not raw:
            return []
        items: List[ScheduledScanResponse] = []
        for ns in raw:
            try:
                items.append(ScheduledScanResponse(
                    id=ns.id,
                    target_id=ns.target_id,
                    scan_id=ns.scan_id,
                    collection_tools=getattr(ns, 'collection_tools', []),
                ))
            except AttributeError as exc:
                logger.warning("Skipping malformed scheduled scan entry: %s", exc)
        return items

    def get_scheduled_scan(self, sched_scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve the full scan configuration for a scheduled scan."""
        return self._get("/api/scheduler/%s/scan/" % sched_scan_id)

    def get_scan_status(self, scan_id: str) -> Optional[Any]:
        """Retrieve the current status of a scan (as a SimpleNamespace)."""
        return self._get("/api/scan/%s/status" % scan_id, as_namespace=True)

    def update_scan_status(self, schedule_scan_id: str, status: int,
                           err_msg: Optional[str] = None) -> bool:
        """Post a scan status update to the server."""
        payload = {"status": status, "error_message": err_msg}
        result = self._post(
            "/api/scheduler/%s/" % schedule_scan_id, payload
        )
        if result is None:
            from reverge_collector.recon_manager import ScanNotFoundException
            raise ScanNotFoundException(
                "Scan %s not found on server" % schedule_scan_id
            )
        return True

    def update_tool_status(self, tool_id: str, status: int,
                           status_message: str = "") -> bool:
        """Post a tool status update."""
        payload = {"status": status, "status_message": status_message}
        self._post("/api/tool/status/%s" % tool_id, payload)
        return True

    def get_tool_status(self, tool_id: str) -> Optional[int]:
        """Retrieve the status value for a tool instance."""
        result = self._get("/api/tool/status/%s" % tool_id, as_namespace=True)
        if result is not None:
            return result.status
        return None

    def collector_poll(self, log_str: Optional[str]) -> Optional[Dict[str, Any]]:
        """Send log data and receive collector configuration settings."""
        payload = {"logs": log_str}
        return self._post("/api/collector/poll", payload, expect_response=True)

    def update_collector(self, collector_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Register or update the collector's capabilities with the server."""
        result = self._post("/api/collector", collector_data, expect_response=True)
        if result is None:
            raise RuntimeError("Error updating collector on server.")
        return result

    def import_data(self, scan_id: str, tool_id: str,
                    scan_results: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Import scan result objects; return server ID-remapping list."""
        payload = {
            "tool_id": tool_id,
            "scan_id": scan_id,
            "obj_list": scan_results,
        }
        result = self._post("/api/data/import", payload, expect_response=True)
        return result if result is not None else []

    def get_wordlist(self, wordlist_id: str) -> Optional[Dict[str, Any]]:
        """Download a wordlist by ID."""
        return self._get("/api/wordlist/%s" % wordlist_id)

    def get_subnets(self, scan_id: str) -> List[str]:
        """Return subnet strings for a scan in ``'network/mask'`` format."""
        result = self._get("/api/subnets/scan/%s" % scan_id, as_namespace=True)
        if not result:
            return []
        subnets = []
        for subnet in result:
            subnets.append("%s/%s" % (subnet.subnet, subnet.mask))
        return subnets

    def get_urls(self, scan_id: str) -> List[str]:
        """Return URL strings associated with a scan."""
        result = self._get("/api/urls/scan/%s" % scan_id, as_namespace=True)
        if not result:
            return []
        return [url_obj.url for url_obj in result]

    def get_hosts(self, scan_id: str) -> List[Any]:
        """Return host objects associated with a scan."""
        result = self._get("/api/hosts/scan/%s" % scan_id, as_namespace=True)
        return result if result is not None else []

    def import_ports(self, port_arr: List[Any]) -> bool:
        """Import raw port data."""
        self._post("/api/ports", port_arr)
        return True

    def import_ports_ext(self, scan_results_dict: Dict[str, Any]) -> bool:
        """Import extended port data."""
        self._post("/api/ports/ext", scan_results_dict)
        return True

    def import_shodan_data(self, scan_id: str, shodan_arr: List[Any]) -> bool:
        """Import Shodan data for a scan."""
        self._post(
            "/api/integration/shodan/import/%s" % str(scan_id), shodan_arr
        )
        return True

    def import_screenshot(self, data_dict: Dict[str, Any]) -> bool:
        """Import a screenshot record."""
        self._post("/api/screenshots", [data_dict])
        return True
