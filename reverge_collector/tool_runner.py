"""
Tool Runner — scan-phase and import-phase idempotency helper.

Replaces ``data_model.ImportToolXOutput`` (the Luigi base class that previously
handled idempotency and result import).

Idempotency checkpoints (matching Luigi's two-task chain exactly)
-----------------------------------------------------------------
Luigi maintained two file-existence checkpoints per tool:

1. **Scan output file** — ``XScan.output()`` e.g. ``ferox_outputs_<id>``.
   Luigi checked this before running ``XScan.run()``.  In the new code,
   ``execute_scan()`` replicates this: return immediately if the file exists.

2. **``tool_import_json``** — ``ImportXOutput.output()`` lived in the same
   directory as the scan output file and was named ``tool_import_json``.
   Luigi checked it before running ``ImportXOutput.run()``.  In the new code,
   call ``import_already_done()`` at the very top of every ``xxx_import()``
   static method, *before* any expensive parsing is attempted.  If it returns
   ``True`` the scope has been restored from the file and the function should
   return ``True`` immediately. After a successful parse + server POST,
   ``import_results()`` writes ``tool_import_json`` so future restarts skip
   the parse step entirely.

Canonical pattern for every tool file
--------------------------------------
::

    from reverge_collector.tool_runner import (
        import_already_done as _import_already_done,
        import_results     as _import_results,
    )

    # --- scan phase ---
    def execute_scan(scan_input) -> None:
        output_file_path = get_output_path(scan_input)
        if os.path.exists(output_file_path):
            return      # checkpoint 1: scan already ran, skip
        # ... scan body ...

    # --- import phase ---
    @staticmethod
    def xxx_import(scan_input) -> bool:
        try:
            output_path = get_output_path(scan_input)
            if not os.path.exists(output_path):
                return True   # scan never ran / no output
            if _import_already_done(scan_input, output_path):
                return True   # checkpoint 2: already imported, scope restored
            ret_arr = parse_xxx_output(output_path, ...)
            _import_results(scan_input, ret_arr, output_path)
            return True
        except Exception as e:
            logging.getLogger(__name__).error(
                "xxx import failed: %s", e, exc_info=True)
            return False
"""

import json
import logging
import os
from typing import Any, List

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Idempotency helpers
# ---------------------------------------------------------------------------

def get_import_marker(output_path: str) -> str:
    """Return the path of the ``tool_import_json`` marker for *output_path*.

    The marker lives in the same directory as the scan output file, mirroring
    Luigi's ``ImportToolXOutput.output()`` placement so that marker files
    written by previous Luigi-based runs are still recognised.
    """
    return os.path.join(os.path.dirname(output_path), "tool_import_json")


def import_already_done(scheduled_scan_obj: Any, output_path: str) -> bool:
    """Check whether the import for *output_path* already completed.

    This is the direct replacement for Luigi's ``ImportToolXOutput.complete()``
    check.  Call it at the very top of every ``xxx_import()`` static method,
    **before** any expensive parsing is attempted.

    If the ``tool_import_json`` marker exists the scope is restored from it
    (matching ``ImportToolXOutput.complete()``'s side-effect) and ``True`` is
    returned so the caller can return immediately without re-parsing or
    re-POSTing to the server.

    Args:
        scheduled_scan_obj: The ``ScheduledScan`` instance whose ``scan_data``
            should be updated when a prior result is found.
        output_path: Absolute path to the scan output file returned by
            ``get_output_path()``.  Used to locate the marker.

    Returns:
        ``True`` if the marker exists (import already done; scope restored).
        ``False`` if the marker is absent (import must be run).
    """
    marker = get_import_marker(output_path)
    if not os.path.exists(marker):
        return False
    try:
        with open(marker) as fh:
            raw = fh.read().strip()
        if raw:
            import_arr = json.loads(raw)
            if import_arr:
                scheduled_scan_obj.scan_data.update(import_arr)
    except Exception as exc:
        logger.warning(
            "Could not restore scope from marker %s: %s", marker, exc)
    return True


# ---------------------------------------------------------------------------
# Result import
# ---------------------------------------------------------------------------

def import_results(
    scheduled_scan_obj: Any,
    obj_arr: List[Any],
    output_path: str,
) -> None:
    """Serialize *obj_arr*, POST to the Reverge API, remap IDs, update scope,
    and write the ``tool_import_json`` marker so the import is skipped on
    subsequent restarts.

    This replaces ``data_model.ImportToolXOutput.import_results()``.

    Args:
        scheduled_scan_obj: The ``ScheduledScan`` instance providing context
            (``scan_id``, ``recon_manager``, ``current_tool.id``, etc.).
        obj_arr: List of ``data_model`` record objects to import.
        output_path: Absolute path to the scan output file returned by
            ``get_output_path()``.  Used to derive the marker location.
    """
    # Deferred import to avoid circular dependency at module load time.
    from reverge_collector import data_model  # noqa: PLC0415

    scan_id = scheduled_scan_obj.scan_id
    recon_manager = scheduled_scan_obj.scan_thread.recon_manager
    tool_id = scheduled_scan_obj.current_tool.id

    if not obj_arr:
        logger.warning("No objects to import for scan %s", scan_id)
        return

    record_map: dict = {}
    import_arr: list = []
    for obj in obj_arr:
        record_map[obj.id] = obj
        import_arr.append(obj.to_jsonable())

    # POST to server and get back the server-assigned ID mapping.
    updated_record_map = recon_manager.import_data(
        scan_id, tool_id, import_arr)

    # Remap local UUIDs → server IDs and collect the updated flat records.
    updated_import_arr = data_model.update_scope_array(
        record_map, updated_record_map)

    # Write the import marker (enables idempotent restarts).
    import_marker = get_import_marker(output_path)
    with open(import_marker, "w") as fh:
        fh.write(json.dumps(updated_import_arr))

    # Update the in-memory scope so later tools in the same session see the
    # newly imported records.
    scheduled_scan_obj.scan_data.update(updated_import_arr)
