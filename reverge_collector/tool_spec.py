"""
ToolSpec — abstract base class for all tool definitions.

Replaces the ``RevergeTool`` (``__init__`` assignments,
identical static scan/import wrappers, duplicated ``get_output_path``
module functions) with:

* **Class-level attribute declarations** for metadata (name, description,
  scan_order, …).  Subclasses set these once at class body level instead
  of in ``__init__``.
* **Default ``scan_func`` / ``import_func``** bound to ``_run_scan`` /
  ``_run_import``, which implement the standard idempotency dance so
  individual tools don't repeat it.
* **Two abstract methods** — ``execute_scan()`` and ``parse_output()`` —
  that every tool must implement.

Canonical subclass pattern::

    class Nmap(ToolSpec):
        name          = 'nmap'
        description   = 'Network scanner'
        project_url   = 'https://github.com/nmap/nmap'
        tags          = ['port-scan', 'slow']
        collector_type = data_model.CollectorType.ACTIVE.value
        scan_order    = 6
        args          = '-sT -sV'
        input_records  = [data_model.ServerRecordType.PORT]
        output_records = [data_model.ServerRecordType.HOST]

        def get_output_path(self, scan_input):
            ...  # only when the default pattern doesn't apply

        def execute_scan(self, scan_input):
            execute_scan(scan_input)   # module-level function

        def parse_output(self, output_path, scan_input):
            return parse_nmap_output(output_path, ...)

Tools that expose Metasploit / Nuclei / Netexec module lists also override
``__init__`` to set ``self.modules_func``::

    def __init__(self):
        super().__init__()
        self.modules_func = Nmap.nmap_modules
"""

import json
import logging
import os
from abc import ABC, abstractmethod
from typing import Any, List, Optional

from reverge_collector import data_model, scan_utils
from reverge_collector.tool_runner import (
    import_already_done as _import_already_done,
)
from reverge_collector.tool_runner import (
    import_batch as _import_batch,
)
from reverge_collector.tool_runner import (
    import_results as _import_results,
)
from reverge_collector.tool_runner import (
    load_pre_import_arr as _load_pre_import_arr,
)
from reverge_collector.tool_runner import (
    post_pre_import as _post_pre_import,
)
from reverge_collector.tool_runner import (
    remove_pre_import_marker as _remove_pre_import_marker,
)
from reverge_collector.tool_runner import (
    write_import_complete_marker as _write_import_complete_marker,
)

logger = logging.getLogger(__name__)


class ToolSpec(data_model.RevergeTool, ABC):
    """Abstract base class for tool specifications.

    Subclasses declare metadata as *class-level* attributes and implement
    ``execute_scan()`` and ``parse_output()``.  Everything else —
    idempotency checks, error logging, status management — is handled here.
    """

    # -----------------------------------------------------------------------
    # Class-level metadata defaults.  Subclasses override these as class attrs,
    # not in __init__.
    # -----------------------------------------------------------------------
    name: str = ''
    description: str = ''
    project_url: str = ''
    tags: List[str] = []
    collector_type: str = data_model.CollectorType.ACTIVE.value
    scan_order: int = 0
    args: str = ''
    input_records: List[Any] = []
    output_records: List[Any] = []
    # Maximum number of URL targets allowed per scan job.  None = unlimited.
    # Set this on slow tools to force users to break large jobs into chunks.
    max_targets: Optional[int] = None
    # Streaming import: when True, ``_run_import`` consumes ``iter_parsed_batches()``
    # and POSTs each batch independently so peak memory stays bounded to one
    # batch rather than the whole parsed result set.  Set this on tools whose
    # output can be very large (e.g. screenshots with embedded base64 blobs).
    streaming_import: bool = False
    # Delete the raw scan output once the import has fully completed.  Useful
    # for tools whose output duplicates what is already persisted server-side
    # (and in ``tool_pre_import_json``), to avoid keeping two large copies.
    delete_output_after_import: bool = False

    # -----------------------------------------------------------------------
    # Initialisation
    # -----------------------------------------------------------------------

    def __init__(self) -> None:
        # Deliberately do NOT call RevergeTool.__init__(): that method would
        # shadow all the class-level metadata attrs above with None.
        # The only instance attrs we need are the callables.
        self.scan_func = self._run_scan
        self.import_func = self._run_import
        self.modules_func = lambda: []
        self.scope_func = lambda: False

    # -----------------------------------------------------------------------
    # Output path — override when the default naming convention doesn't apply
    # -----------------------------------------------------------------------

    def get_output_path(self, scan_input: 'data_model.ScheduledScan') -> str:
        """Return the path to the primary scan output file.

        Default: ``<tool_outputs_dir>/<tool_name>_outputs_<scan_id>``

        Override this method in subclasses whose output files use a different
        naming scheme (e.g. ``.json``, ``.meta``, custom prefix).
        """
        scan_id: str = scan_input.id
        tool_name: str = scan_input.current_tool.name
        dir_path: str = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)
        return f'{dir_path}{os.path.sep}{tool_name}_outputs_{scan_id}'

    # -----------------------------------------------------------------------
    # Default scan_func / import_func implementations
    # -----------------------------------------------------------------------

    def _write_scan_inputs(self, scan_input: 'data_model.ScheduledScan') -> None:
        """Write a JSON summary of scan inputs to the tool's inputs folder."""
        scan_id: str = scan_input.id
        tool_name: str = scan_input.current_tool.name
        scope_obj = scan_input.scan_data

        dir_path: str = scan_utils.init_tool_folder(tool_name, 'inputs', scan_id)
        input_file: str = f'{dir_path}{os.sep}{tool_name}_scan_input_{scan_id}.json'

        hosts = [h.ipv4_addr for h in scope_obj.get_hosts() if h.ipv4_addr]
        domains = [d.name for d in scope_obj.get_domains() if d.name]

        ports = []
        for key, entry in scope_obj.host_port_obj_map.items():
            host_obj = entry['host_obj']
            port_obj = entry['port_obj']
            ports.append(
                {
                    'ip': host_obj.ipv4_addr,
                    'port': port_obj.port,
                    'proto': port_obj.proto,
                    'secure': port_obj.secure,
                }
            )

        if len(ports) == 0:
            ports = scope_obj.get_port_number_list_from_scope()

        subnets = []
        for subnet_obj in scope_obj.subnet_map.values():
            if subnet_obj.subnet and subnet_obj.mask:
                subnets.append(f'{subnet_obj.subnet}/{subnet_obj.mask}')

        input_data = {
            'scan_id': scan_id,
            'tool': tool_name,
            'hosts': sorted(set(hosts)),
            'domains': sorted(set(domains)),
            'ports': ports,
            'subnets': sorted(set(subnets)),
        }
        try:
            with open(input_file, 'w') as fd:
                fd.write(json.dumps(input_data, indent=2))
        except Exception as e:
            logger.warning('%s: failed to write scan inputs: %s', tool_name, e)

    def _run_scan(self, scan_input: 'data_model.ScheduledScan') -> bool:
        """Calls ``execute_scan()`` and returns True on success."""

        try:
            self._write_scan_inputs(scan_input)
            self.execute_scan(scan_input)
            return True
        except Exception as e:
            logger.error('%s scan failed: %s', self.name, e, exc_info=True)
            raise

    def _run_import(self, scan_input: 'data_model.ScheduledScan') -> bool:
        """Standard idempotent import: exists-check → already-done → parse → POST.

        Retry path: if ``tool_pre_import_json`` exists (parse completed but
        POST was interrupted) the cached serialised records are re-POSTed
        directly without re-parsing the raw tool output.
        """
        try:
            output_path = self.get_output_path(scan_input)
            # Completion marker wins regardless of whether the raw output still
            # exists (a tool may delete it after importing): restore scope, skip.
            if _import_already_done(scan_input, output_path):
                return True

            if self.streaming_import:
                return self._run_streaming_import(scan_input, output_path)

            # Retry path: parse already done but POST was interrupted.
            pre_import_arr = _load_pre_import_arr(output_path)
            if pre_import_arr is not None:
                logger.info(
                    '%s: pre-import cache found — retrying POST without re-parsing',
                    self.name,
                )
                _post_pre_import(scan_input, pre_import_arr, output_path)
                return True
            # No cached state — we need the raw output to parse from.
            if not os.path.exists(output_path):
                return True
            ret_arr = self.parse_output(output_path, scan_input)
            _import_results(scan_input, ret_arr, output_path)
            if self.delete_output_after_import:
                self._safe_remove(output_path)
            return True
        except Exception as e:
            logger.error('%s import failed: %s', self.name, e, exc_info=True)
            raise

    def _run_streaming_import(
        self, scan_input: 'data_model.ScheduledScan', output_path: str
    ) -> bool:
        """Memory-bounded import for tools with large output.

        The raw output file is the source of truth.  We stream it in batches
        and POST each batch independently, so peak memory stays bounded to one
        batch rather than the whole result set.  Re-running after an interrupted
        import is safe: the server dedups by record hash, so anything POSTed
        before a crash collapses rather than duplicates.

        Crucially, this path does **not** consult the whole-file
        ``tool_pre_import_json`` cache while the raw output exists — loading and
        POSTing that giant blob in one shot is the exact unbounded-memory crash
        streaming exists to avoid.  It's only used as a last-resort fallback if
        the raw output is already gone.
        """
        if os.path.exists(output_path):
            for batch in self.iter_parsed_batches(output_path, scan_input):
                _import_batch(scan_input, batch)
            _write_import_complete_marker(output_path)
            # Reclaim disk: drop the raw output and any stale whole-file
            # pre-import cache left by a previous (pre-streaming) run.
            _remove_pre_import_marker(output_path)
            if self.delete_output_after_import:
                self._safe_remove(output_path)
            return True

        # Raw output gone but not marked complete — best-effort re-POST from a
        # cached pre-import array if a prior run left one.
        pre_import_arr = _load_pre_import_arr(output_path)
        if pre_import_arr is not None:
            _post_pre_import(scan_input, pre_import_arr, output_path)
        return True

    def _safe_remove(self, path: str) -> None:
        """Remove *path*, logging (not raising) on failure."""
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            logger.warning('%s: could not delete %s after import: %s', self.name, path, exc)

    # -----------------------------------------------------------------------
    # Abstract interface — every tool must implement these two methods
    # -----------------------------------------------------------------------

    @abstractmethod
    def execute_scan(self, scan_input: 'data_model.ScheduledScan') -> None:
        """Run the tool and write output to ``get_output_path()``.

        Passive / API-based tools fetch from their API here and write the
        result to disk so that ``_run_import`` can pick it up.
        """

    @abstractmethod
    def parse_output(
        self,
        output_path: str,
        scan_input: 'data_model.ScheduledScan',
    ) -> List[Any]:
        """Parse tool output and return a list of ``data_model.Record`` objects."""

    # -----------------------------------------------------------------------
    # Streaming import hook — override when ``streaming_import`` is True
    # -----------------------------------------------------------------------

    def iter_parsed_batches(
        self,
        output_path: str,
        scan_input: 'data_model.ScheduledScan',
    ):
        """Yield successive batches (lists) of records for streaming import.

        Only invoked when ``streaming_import`` is True.  Tools that set that
        flag must override this to parse their output incrementally so peak
        memory stays bounded to a single batch.  The default raises to make a
        missing override obvious.
        """
        raise NotImplementedError(
            f'{self.name}: streaming_import is set but iter_parsed_batches() is not implemented'
        )
