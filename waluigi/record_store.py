"""
RecordStore — auto-indexed backing store for ScanData records.

Consolidates the 38+ manually-synchronised dicts that previously lived
directly in ``ScanData.__init__`` into a single object with a generic
``add()`` entry-point.  ``ScanData`` keeps all existing attribute names as
``@property`` delegates to this store so that callers are unaffected.

Index declarations
------------------
Each ``Record`` subclass declares a class-level ``_indices`` list that
describes how that record should be indexed.  ``RecordStore.add()``
iterates the declarations and maintains the indices generically, so
adding a new record type never requires touching this module.

An index entry is a tuple of ``(store_attr, key_func, mode)``:

* **store_attr** — the name of the ``RecordStore`` attribute (e.g.
  ``"host_map"``).
* **key_func** — a callable ``(record) -> key_value``.  When the
  return value is ``None`` the entry is silently skipped.
* **mode** — how the value is stored:

  - ``"map"``   → ``store[key] = record``             (1:1 by record id)
  - ``"map_id"`` → ``store[key] = record.id``         (1:1 by id value)
  - ``"list"``  → ``store[key].append(record)``       (1:N)
  - ``"list_id"`` → ``store[key].append(record.id)``  (1:N of ids)
  - ``"set"``   → ``store[key].add(value)``           (1:N set, key_func
    returns ``(set_key, value)``)

Records may also implement an optional ``_pre_index(store)`` classmethod
hook for one-off logic that doesn't fit the declarative model (e.g.
preserving credentials across Host updates).
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Set, Tuple

# Index mode constants
MAP: str = "map"
MAP_ID: str = "map_id"
LIST: str = "list"
LIST_ID: str = "list_id"
LIST_VALUE: str = "list_value"
SET: str = "set"

# Type alias for an index declaration tuple
IndexEntry = Tuple[str, Callable, str]


class RecordStore:
    """
    Central indexed store for all ``Record`` subtypes produced during a scan.

    Attributes mirror every mapping dict that used to be initialised directly
    in ``ScanData.__init__``.  ``add()`` reads the ``_indices`` declarations
    on each record's class and maintains indices generically.
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

        Reads the ``_indices`` class-level list on the record's type and
        maintains indices generically.  Records may also provide a
        ``_pre_index(store)`` hook for logic that doesn't fit the
        declarative model.
        """
        # Allow a record to run custom pre-index logic (e.g. credential
        # preservation on Host)
        pre_index = getattr(record_obj, '_pre_index', None)
        if pre_index is not None:
            pre_index(self)

        # Process declarative indices
        indices: List[IndexEntry] = getattr(
            record_obj.__class__, '_indices', None)
        if indices:
            for store_attr, key_func, mode in indices:
                key = key_func(record_obj)
                if key is None:
                    continue

                index = getattr(self, store_attr)
                if mode == MAP:
                    index[key] = record_obj
                elif mode == MAP_ID:
                    index[key] = record_obj.id
                elif mode == LIST:
                    index.setdefault(key, []).append(record_obj)
                elif mode == LIST_ID:
                    index.setdefault(key, []).append(record_obj.id)
                elif mode == LIST_VALUE:
                    list_key, value = key
                    index.setdefault(list_key, []).append(value)
                elif mode == SET:
                    set_key, value = key
                    index.setdefault(set_key, set()).add(value)

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
