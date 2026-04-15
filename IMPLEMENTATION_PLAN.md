# Waluigi Collector — Refactoring Implementation Plan

**Branch:** `refactor/architecture-overhaul`  
**Baseline:** See `ARCHITECTURE_REVIEW.md` for the full problem analysis.

---

## Phasing Strategy

The changes are ordered to minimize risk and maximize incremental value. Each phase produces a working, testable system before the next phase begins. Phases 1–3 are structural refactors with no behavior change. Phases 4–6 introduce new abstractions.

---

## Phase 1: Extract ApiClient from ReconManager

**Goal:** Separate HTTP transport/encryption from scan orchestration.  
**Risk:** Low — purely additive extraction, ReconManager delegates to new class.  
**Files touched:** `recon_manager.py`, new `api_client.py`, `tool_utils.py`

### Steps

1.1. Create `waluigi/api_client.py` with class `ApiClient`:
  - Move encryption methods from `tool_utils.py`: `get_session_key()`, `encrypt_data()`, `decrypt_data()`
  - Move all HTTP methods from `ReconManager`: `import_data()`, `get_scheduled_scans()`, `update_scan_status()`, `update_tool_status()`, `get_scan_status()`, `collector_poll()`, `get_connection_manager()`, `get_wordlist()`, `get_cert_chain()`
  - Encapsulate the encrypt → POST → check status → decrypt pattern into a generic `_request()` method
  - Store `session_key`, `headers`, `manager_url` as instance state
  - Add retry logic with configurable backoff

1.2. Refactor `ReconManager.__init__()`:
  - Instantiate `ApiClient` and store as `self.api`
  - Delegate all HTTP calls through `self.api`
  - Keep tool registration, interface discovery, and orchestration logic in `ReconManager`

1.3. Update imports in `recon_manager.py` — remove direct `requests` usage from ReconManager methods.

1.4. Re-export `encrypt_data` from `tool_utils.py` for backward compat (other files import it from there).

1.5. **Validation:** Run existing scans end-to-end. Behavior should be identical.

---

## Phase 2: Remove Luigi

**Goal:** Replace Luigi task wrappers with direct function calls.  
**Risk:** Medium — touches all 17 tool files + `data_model.py` + `recon_manager.py`.  
**Strategy:** Change the framework plumbing first, then update tools one at a time.  
**Files touched:** `data_model.py`, `recon_manager.py`, all 17 tool files, `requirements.txt`

### Steps

2.1. Create `waluigi/tool_runner.py` — the Luigi replacement:
  - Function `run_scan(tool_module, scan_input) -> str`:
    - Calls `tool_module.execute_scan(scan_input)` → returns output path
    - No Luigi task, no `output()` / `complete()` boilerplate
  - Function `run_import(tool_module, scan_input, output_path) -> List[Record]`:
    - Calls `tool_module.parse_output(output_path, scan_input)` → returns record list
    - Calls `import_results(scan_input, records)` directly (logic extracted from `ImportToolXOutput`)
    - Updates scope in-memory (no disk write + re-read cycle)
  - Function `import_results(scan_input, obj_arr)`:
    - Extracted from `ImportToolXOutput.import_results()` and `ImportToolXOutput.complete()`
    - Serialize → POST → remap IDs → update scope (single pass, no disk round-trip)

2.2. Refactor `data_model.py`:
  - Remove `class ImportToolXOutput(luigi.Task)` entirely
  - Remove `import luigi`
  - Keep the `import_results` logic as a standalone function in `tool_runner.py`

2.3. Refactor `ScheduledScanThread.execute_scan_jobs()` in `recon_manager.py`:
  - Replace `luigi.build([ScanTask(...)])` calls with `tool_runner.run_scan()`
  - Replace `luigi.build([ImportTask(...)])` calls with `tool_runner.run_import()`
  - Remove the `failed_task_exception` static-variable hack
  - Use standard try/except for error propagation

2.4. Refactor each tool file (batch — all follow identical pattern):
  - Remove `import luigi`, `from luigi.util import inherits`
  - Remove the `ToolScan(luigi.Task)` class — extract `run()` body into a module-level `execute_scan(scan_input) -> str` function
  - Remove the `ImportToolOutput(ImportToolXOutput)` class — extract parse call into a module-level `parse_output(output_path, scan_input) -> List[Record]` function
  - Update `WaluigiTool` subclass: `scan_func` / `import_func` now point to the new module-level functions directly (no `luigi.build` wrapper)

  Tool migration order (by complexity, simplest first):
  1. `python_scan.py` (296 lines)
  2. `iis_short_scan.py` (342 lines)
  3. `sqlmap_scan.py` (566 lines)
  4. `gau_scan.py` (570 lines)
  5. `pyshot_scan.py` (582 lines)
  6. `subfinder_scan.py` (625 lines)
  7. `nuclei_scan.py` (641 lines)
  8. `feroxbuster_scan.py` (722 lines)
  9. `httpx_scan.py` (731 lines)
  10. `nmap_scan.py` (816 lines)
  11. `webcap_scan.py` (884 lines)
  12. `shodan_lookup.py` (926 lines)
  13. `ip_thc_lookup.py` (1065 lines)
  14. `crapsecrets_scan.py` (1121 lines)
  15. `masscan.py` (1192 lines)
  16. `metasploit_scan.py` (1394 lines)
  17. `netexec_scan.py` (1406 lines)

2.5. Remove `luigi` from `requirements.txt`.

2.6. **Validation:** Run each tool individually after migration. Full end-to-end scan after all tools migrated.

---

## Phase 3: Typed Records with Dataclasses

**Goal:** Replace hand-rolled serialization with declarative dataclass records. Eliminate the `isinstance` chains in `static_from_jsonsable()`, `_process_data()`, and `update_scope_array()`.  
**Risk:** Medium — changes the core data contract, but the JSON wire format stays the same.  
**Files touched:** `data_model.py`, all 17 tool parsers (record construction sites)

### Steps

3.1. Define a `@record` decorator or base metaclass that:
  - Auto-generates `to_jsonable()` / `from_jsonsable()` from field declarations
  - Registers the class in a global `RECORD_REGISTRY: Dict[str, Type[Record]]` keyed by lowercase class name
  - Declares `ForeignKey` fields that participate in ID remapping automatically

3.2. Convert each Record subclass to a dataclass (one at a time, test after each):
  ```python
  @dataclass
  class Host(Record):
      record_type = "host"
      ipv4_addr: Optional[str] = None
      ipv6_addr: Optional[str] = None
      credential: Optional[str] = None
  ```

  Migration order:
  1. `Host` (simplest, no foreign keys)
  2. `Subnet`
  3. `Port` (parent: Host)
  4. `Domain` (parent: Host)
  5. `Tool`
  6. `ListItem`
  7. `Screenshot`
  8. `WebComponent` (parent: Port)
  9. `Certificate` (parent: Port, has `domain_id_list`)
  10. `Vuln` (parent: Port)
  11. `HttpEndpoint` (parent: Port, FK: `web_path_id`)
  12. `HttpEndpointData` (parent: HttpEndpoint, FKs: `domain_id`, `screenshot_id`)
  13. `Credential`
  14. `CollectionModule` (parent: Tool)
  15. `CollectionModuleOutput` (parent: CollectionModule)
  16. `OperatingSystem`

3.3. Replace `Record.static_from_jsonsable()`:
  - Use `RECORD_REGISTRY[type_str]` lookup instead of `if/elif` chain
  - Call the generated `from_jsonsable()` method

3.4. Replace `update_scope_array()`:
  - Iterate all records, call `record.remap_ids(id_updates)` — each record's FK fields are remapped automatically by the base class using the `ForeignKey` declarations

3.5. Update all 17 tool parsers:
  - Record construction stays similar (`Host(ipv4_addr="...")`) but uses dataclass constructors
  - Remove manual `obj.collection_tool_instance_id = ...` lines — move to constructor kwarg

3.6. **Validation:** Serialize a known set of records, compare JSON output byte-for-byte with the old implementation. Round-trip test: serialize → deserialize → serialize and verify equality.

---

## Phase 4: Declarative Tool Specs

**Goal:** Collapse boilerplate across 17 tool files into a base class. Each tool defines only its unique logic.  
**Risk:** Low-Medium — each tool can be migrated independently.  
**Files touched:** New `waluigi/tool_spec.py`, all 17 tool files, `data_model.py` (WaluigiTool)

### Steps

4.1. Create `waluigi/tool_spec.py` with abstract base class `ToolSpec`:
  ```python
  class ToolSpec(ABC):
      name: str
      scan_order: int
      collector_type: CollectorType
      input_records: List[ServerRecordType]
      output_records: List[ServerRecordType]

      def build_commands(self, scan_data: ScanData, scan_input: ScheduledScan) -> List[Command]:
          """Return list of Command objects (binary path + args + output path)."""
          ...

      def parse_output(self, output_paths: List[str], tool_instance_id: str, scan_data: ScanData) -> List[Record]:
          """Parse tool output files into Record objects."""
          ...

      # Optional overrides:
      def pre_scan(self, scan_input): pass
      def post_scan(self, scan_input): pass
  ```

4.2. Create `waluigi/command.py` — lightweight `Command` dataclass:
  ```python
  @dataclass
  class Command:
      args: List[str]
      output_path: str
      sudo: bool = True
      env: Optional[Dict[str, str]] = None
  ```

4.3. Update `tool_runner.py` to handle `ToolSpec`:
  - `run_scan()`: calls `spec.build_commands()`, executes each via `process_wrapper()`, manages futures
  - `run_import()`: calls `spec.parse_output()`, then `import_results()`
  - Handles the PID callback / registration pattern generically

4.4. Migrate tools one at a time to `ToolSpec` (same order as Phase 2). For each:
  - Extract target selection logic → `build_commands()`
  - Keep parsing function as-is → `parse_output()`
  - Delete Luigi classes, static `scan_func` / `import_func`, `output()` boilerplate
  - Expected line reduction: 40-60% per file

4.5. Merge `WaluigiTool` metadata into `ToolSpec` — single class for tool definition.

4.6. Update `data_model.waluigi_tools` list to reference `ToolSpec` subclasses directly instead of `(module, class_name)` tuples.

4.7. **Validation:** Run each tool after migration. Compare scan results against baseline captures.

---

## Phase 5: Simplify ScanData

**Goal:** Replace 20+ manually-synchronized dictionaries with an auto-indexed record store.  
**Risk:** Medium-High — ScanData is accessed everywhere; all tools read from it.  
**Files touched:** `data_model.py`, all tool files that read `scan_data.*_map`

### Steps

5.1. Create `waluigi/record_store.py` — `RecordStore` class:
  - Single `records: Dict[str, Record]` backing store
  - Auto-maintained indices declared per record type:
    ```python
    class Host(Record):
        indices = {
            'by_ip': lambda h: h.ipv4_addr,
        }
    ```
  - Generic methods: `add(record)`, `get(id)`, `query(type, index_name, key)`, `remove(id)`
  - Index updates happen automatically on `add()` / `remove()`

5.2. Add compatibility properties to `RecordStore`:
  - `host_map`, `port_map`, `domain_map`, etc. as computed properties that return the appropriate index
  - This allows gradual migration — old code reads `scan_data.host_map[id]` and it still works

5.3. Replace `ScanData.__init__()` map initialization with `RecordStore()`.

5.4. Replace `ScanData._process_data()` — use `store.add(record)` instead of per-type `isinstance` branches.

5.5. Replace `ScanData.update()` with `store.add()` calls.

5.6. Migrate tool files to use `store.query()` instead of direct map access (can be done gradually using the compat properties).

5.7. Remove the compat properties once all consumers are migrated.

5.8. **Validation:** Snapshot all map contents before and after refactor for a known scan, diff to verify equivalence.

---

## Phase 6: Resource Management & Hardening

**Goal:** Fix process leaks, add concurrency limits, improve security posture.  
**Risk:** Low — targeted fixes, no structural changes.  
**Files touched:** `recon_manager.py`, `scan_utils.py`, `data_model.py`, `api_client.py`

### Steps

6.1. Create `waluigi/process_handle.py` — unified `ProcessHandle`:
  - Wraps both `Future` and PID in one object
  - Automatic cleanup callback on completion
  - `kill()` method that handles SIGKILL + future cancellation + map removal

6.2. Add bounded concurrency:
  - `ScheduledScanThread`: configurable `max_concurrent_scans` (default: 3)
  - Use a `Semaphore` to gate new scan threads

6.3. Fix tool executor memory leak:
  - `register_tool_executor()`: add a `Future.add_done_callback()` that removes the executor from the map on completion

6.4. Session key security:
  - Store session key in memory only (remove disk caching to `./session` file)
  - If persistence is required, use OS keyring or file with `0600` permissions

6.5. Replace `SimpleNamespace` deserialization in `get_scheduled_scans()`:
  - Use the typed dataclass models from Phase 3 or at minimum a `TypedDict`

6.6. SSL verification:
  - Add `verify_ssl` config option to `ApiClient` (default: `True`)
  - Allow override via environment variable for dev/test

6.7. **Validation:** Long-running soak test — run collector for extended period, monitor memory usage. Verify no leaked processes via `ps`.

---

## Dependency Graph Between Phases

```
Phase 1 (ApiClient)
    │
    ▼
Phase 2 (Remove Luigi)  ──► Phase 4 (Tool Specs)
    │                             │
    ▼                             ▼
Phase 3 (Typed Records) ──► Phase 5 (RecordStore)
                                  │
                                  ▼
                            Phase 6 (Hardening)
```

- **Phases 1 and 2** can proceed in parallel (independent code paths)
- **Phase 3** depends on Phase 2 (ImportToolXOutput must be removed first)
- **Phase 4** depends on Phase 2 (Luigi wrappers must be gone first)
- **Phase 5** depends on Phase 3 (records must be dataclasses for auto-indexing)
- **Phase 6** can start after Phase 1 and proceed in parallel with later phases

---

## Estimated Scope

| Phase | Files Changed | Lines Added | Lines Removed | Net |
|-------|--------------|-------------|---------------|-----|
| 1. ApiClient | 3 | ~400 | ~300 | +100 |
| 2. Remove Luigi | 20 | ~200 | ~600 | -400 |
| 3. Typed Records | 18 | ~300 | ~500 | -200 |
| 4. Tool Specs | 18 | ~200 | ~1500 | -1300 |
| 5. RecordStore | 18 | ~250 | ~400 | -150 |
| 6. Hardening | 4 | ~150 | ~50 | +100 |
| **Total** | — | **~1500** | **~3350** | **-1850** |

Net reduction of ~1,850 lines while improving type safety, testability, and maintainability.
