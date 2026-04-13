"""
RecordStore — auto-indexed backing store for ScanData records.

Consolidates the 38+ manually-synchronised dicts that previously lived
directly in ``ScanData.__init__`` into a single object with a generic
``add()`` entry-point.  ``ScanData`` keeps all existing attribute names as
``@property`` delegates to this store so that callers are unaffected.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple


class RecordStore:
    """
    Central indexed store for all ``Record`` subtypes produced during a scan.

    Attributes mirror every mapping dict that used to be initialised directly
    in ``ScanData.__init__``.  ``add()`` replaces the ``isinstance``-dispatch
    block of ``ScanData._process_data()``.
    """

    def __init__(self) -> None:
        # ── universal map ────────────────────────────────────────────────────
        self.scan_obj_map: Dict[str, Any] = {}

        # ── network infrastructure ───────────────────────────────────────────
        self.subnet_map: Dict[str, Any] = {}
        self.host_map: Dict[str, Any] = {}
        self.host_ip_id_map: Dict[str, str] = {}
        self.credential_map: Dict[str, Any] = {}

        # ── host-port derived ────────────────────────────────────────────────
        # "IP:port" / "domain:port" → {host_obj, port_obj}
        self.host_port_obj_map: Dict[str, Dict[str, Any]] = {}

        # ── domain ───────────────────────────────────────────────────────────
        self.domain_name_map: Dict[str, Any] = {}
        self.domain_map: Dict[str, Any] = {}
        self.domain_host_id_map: Dict[str, List[Any]] = {}
        self.domain_port_id_map: Dict[str, Tuple[str, str]] = {}

        # ── ports ────────────────────────────────────────────────────────────
        self.port_map: Dict[str, Any] = {}
        self.port_host_map: Dict[str, Set[str]] = {}
        self.host_id_port_map: Dict[str, List[Any]] = {}

        # ── web components ───────────────────────────────────────────────────
        self.component_map: Dict[str, Any] = {}
        self.component_port_id_map: Dict[str, List[Any]] = {}
        self.component_name_port_id_map: Dict[str, List[str]] = {}
        self.module_name_component_map: Dict[str, List[Any]] = {}

        # ── paths & screenshots ──────────────────────────────────────────────
        self.path_map: Dict[str, Any] = {}
        self.path_hash_id_map: Dict[str, List[str]] = {}
        self.screenshot_map: Dict[str, Any] = {}
        self.screenshot_hash_id_map: Dict[str, List[str]] = {}

        # ── HTTP endpoints ───────────────────────────────────────────────────
        self.http_endpoint_map: Dict[str, Any] = {}
        self.http_endpoint_port_id_map: Dict[str, List[Any]] = {}
        self.http_endpoint_path_id_map: Dict[str, List[Any]] = {}
        self.http_endpoint_data_screenshot_id_map: Dict[str, List[Any]] = {}
        self.http_endpoint_data_map: Dict[str, Any] = {}
        self.endpoint_data_endpoint_id_map: Dict[str, List[Any]] = {}

        # ── collection modules ───────────────────────────────────────────────
        self.collection_module_map: Dict[str, Any] = {}
        self.module_name_id_map: Dict[str, List[Any]] = {}
        self.collection_module_output_map: Dict[str, Any] = {}
        self.collection_module_output_port_id_map: Dict[str, List[Any]] = {}
        self.module_output_module_id_map: Dict[str, List[Any]] = {}

        # ── vulnerabilities ──────────────────────────────────────────────────
        self.vulnerability_map: Dict[str, Any] = {}
        self.vulnerability_name_id_map: Dict[str, List[Any]] = {}

        # ── certificates ─────────────────────────────────────────────────────
        self.certificate_map: Dict[str, Any] = {}
        self.certificate_port_id_map: Dict[str, List[Any]] = {}

        # ── misc modules ─────────────────────────────────────────────────────
        self.module_map: Dict[str, Any] = {}
        self.component_name_module_map: Dict[str, List[Any]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add(self, record_obj: Any) -> None:
        """
        Add *record_obj* to the store and update every relevant index.

        The import is deferred to avoid a circular dependency with
        ``data_model``, which imports ``RecordStore`` at module level.
        """
        # Lazy import to break the circular dependency:
        # data_model → record_store → data_model
        from waluigi.data_model import (
            Host, Domain, Port, ListItem, WebComponent, Screenshot,
            HttpEndpoint, HttpEndpointData, Vuln, CollectionModule,
            CollectionModuleOutput, Certificate, Subnet, Credential,
        )

        if isinstance(record_obj, Host):
            host_ip = record_obj.ipv4_addr

            # Preserve credential from any previous Host with the same IP
            if host_ip in self.host_ip_id_map:
                old_host_id = self.host_ip_id_map[host_ip]
                if old_host_id in self.host_map:
                    record_obj.credential = self.host_map[old_host_id].credential

            self.host_ip_id_map[host_ip] = record_obj.id
            self.host_map[record_obj.id] = record_obj

        elif isinstance(record_obj, Domain):
            host_id = record_obj.parent.id
            self.domain_host_id_map.setdefault(host_id, []).append(record_obj)
            self.domain_name_map[record_obj.name] = record_obj
            self.domain_map[record_obj.id] = record_obj

        elif isinstance(record_obj, Port):
            host_id = record_obj.parent.id
            self.host_id_port_map.setdefault(host_id, []).append(record_obj)

            port_str = record_obj.port
            self.port_host_map.setdefault(port_str, set()).add(host_id)

            self.port_map[record_obj.id] = record_obj

        elif isinstance(record_obj, ListItem):
            if record_obj.web_path_hash:
                path_hash = record_obj.web_path_hash.upper()
                self.path_hash_id_map.setdefault(path_hash, []).append(record_obj.id)
            self.path_map[record_obj.id] = record_obj

        elif isinstance(record_obj, WebComponent):
            port_id = record_obj.parent.id
            self.component_port_id_map.setdefault(port_id, []).append(record_obj)

            component_key = record_obj.name
            if record_obj.version:
                component_key += ":" + record_obj.version
            self.component_name_port_id_map.setdefault(component_key, []).append(port_id)

            self.component_map[record_obj.id] = record_obj

        elif isinstance(record_obj, Screenshot):
            if record_obj.image_hash:
                img_hash = record_obj.image_hash.upper()
                self.screenshot_hash_id_map.setdefault(img_hash, []).append(record_obj.id)
            self.screenshot_map[record_obj.id] = record_obj

        elif isinstance(record_obj, HttpEndpoint):
            web_path_id = record_obj.web_path_id
            self.http_endpoint_path_id_map.setdefault(web_path_id, []).append(record_obj)

            port_id = record_obj.parent.id
            self.http_endpoint_port_id_map.setdefault(port_id, []).append(record_obj)

            self.http_endpoint_map[record_obj.id] = record_obj

        elif isinstance(record_obj, HttpEndpointData):
            http_endpoint_id = record_obj.parent.id
            self.endpoint_data_endpoint_id_map.setdefault(http_endpoint_id, []).append(record_obj)

            screenshot_id = record_obj.screenshot_id
            self.http_endpoint_data_screenshot_id_map.setdefault(screenshot_id, []).append(record_obj)

            self.http_endpoint_data_map[record_obj.id] = record_obj

        elif isinstance(record_obj, Vuln):
            vuln_name = record_obj.name
            self.vulnerability_name_id_map.setdefault(vuln_name, []).append(record_obj)
            self.vulnerability_map[record_obj.id] = record_obj

        elif isinstance(record_obj, CollectionModule):
            module_name = record_obj.name
            self.module_name_id_map.setdefault(module_name, []).append(record_obj)
            self.collection_module_map[record_obj.id] = record_obj

        elif isinstance(record_obj, CollectionModuleOutput):
            module_id = record_obj.parent.id
            self.module_output_module_id_map.setdefault(module_id, []).append(record_obj)

            port_id = record_obj.port_id
            self.collection_module_output_port_id_map.setdefault(port_id, []).append(record_obj)

            self.collection_module_output_map[record_obj.id] = record_obj

        elif isinstance(record_obj, Certificate):
            port_id = record_obj.parent.id
            self.certificate_port_id_map.setdefault(port_id, []).append(record_obj)
            self.certificate_map[record_obj.id] = record_obj

        elif isinstance(record_obj, Subnet):
            self.subnet_map[record_obj.id] = record_obj

        elif isinstance(record_obj, Credential):
            self.credential_map[record_obj.id] = record_obj

        # Always add to the universal map
        self.scan_obj_map[record_obj.id] = record_obj

    def get(self, record_id: str) -> Optional[Any]:
        """Return the record with *record_id*, or ``None`` if not present."""
        return self.scan_obj_map.get(record_id)

    def query(self, index_name: str, key: Any) -> Any:
        """
        Generic index lookup.

        Parameters
        ----------
        index_name:
            Name of the index attribute on this store (e.g. ``"host_map"``,
            ``"port_host_map"``).
        key:
            Key to look up in the index.

        Returns
        -------
        The value stored at *key* in the named index, or ``None``.
        """
        index = getattr(self, index_name, None)
        if index is None:
            return None
        return index.get(key)

    def remove(self, record_id: str) -> None:
        """Remove *record_id* from the universal map (indices are not pruned)."""
        self.scan_obj_map.pop(record_id, None)
