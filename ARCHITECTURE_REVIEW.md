# Waluigi Collector — Architectural Review

**Date:** April 12, 2026  
**Scope:** Data flow design, framework dependencies, serialization, tool wrapper patterns

---

## Data Flow Overview

```
Server                          Collector
──────                          ─────────
GET /api/scheduler/ ──────────► ScheduledScanThread.run()
  (encrypted scan config)         │
                                  ├─ Deserialize → ScanData (20+ dicts)
                                  ├─ For each tool (sorted by scan_order):
                                  │    ├─ luigi.build([ToolScan])
                                  │    │    └─ subprocess → tool binary → output file
                                  │    └─ luigi.build([ImportToolOutput])
                                  │         ├─ parse output → List[Record]
                                  │         ├─ Record.to_jsonable() → flat dicts
POST /api/data/import ◄──────────┤         ├─ encrypt + POST to server
  (encrypted JSON blob)          │         ├─ receive ID remappings
  ──────────────────────►        │         ├─ update_scope_array() remap IDs
                                  │         └─ ScanData.update() merge into scope
                                  └─ update_scan_status(COMPLETED)
```

---

## 1. Luigi: Overhead Without Benefit

Luigi is designed for complex DAG pipelines with fan-out dependencies, caching, retries, and a central scheduler. Waluigi uses **none of these features**:

- **Every tool is a trivial 2-task chain**: `ToolScan → ImportToolOutput`. There are no DAGs, no fan-out, no conditional branches.
- **`local_scheduler=True` everywhere**: The central Luigi scheduler is never used. Each `luigi.build()` call spins up a throwaway local scheduler, runs one task, and exits.
- **`output()` / `complete()` are misused**: Luigi's file-based completion markers are used not for caching but as a side-channel to re-inject scope data on resumption. The `complete()` method has the side effect of mutating `ScanData`, which breaks Luigi's assumption that `complete()` is a pure idempotency check.
- **Error handling fights Luigi**: A static variable `failed_task_exception` is used to smuggle exceptions out of Luigi tasks back to the calling thread because Luigi swallows task exceptions.
- **The `@inherits` decorator** copies `scan_input` across tasks, but `scan_input` is a mutable `ScheduledScan` object passed by reference — Luigi parameters are meant to be serializable, immutable values.

**Recommendation**: Replace Luigi with direct function calls. Each tool already has a `scan_func` and `import_func` that are static methods — just call them sequentially. The scan-order sorting in `execute_scan_jobs` already handles orchestration. This eliminates ~200 lines of wrapper boilerplate, removes the Luigi dependency, and makes error propagation straightforward.

---

## 2. Serialization: Fragile, Manual, and Redundant

The serialization layer has several structural problems:

**a) Hand-rolled type dispatch everywhere.** `Record.static_from_jsonsable()` is a giant `if/elif` chain matching string type names to classes. Adding a new record type requires updating this factory, the `ScanData._process_data()` method (another `isinstance` chain), and `update_scope_array()` (yet another `isinstance` check for special fields like `web_path_id`, `domain_id`, `screenshot_id`). This is a classic open/closed principle violation.

**b) No schema validation.** Records are deserialized from server JSON with bare `input_dict['id']` lookups wrapped in a catch-all `except Exception`. A missing field or type mismatch produces an opaque error. There's no contract between client and server — the JSON shape is implicit in scattered `_data_to_jsonable()` / `from_jsonsable()` methods across 15+ classes.

**c) Double serialization on import.** In `import_results()`, objects are serialized to JSON (`to_jsonable()`), POSTed to the server, then the ID-remapped objects are serialized *again* to write to disk, then deserialized *again* in `complete()` to update scope. That's 3 serialize/deserialize cycles for one import.

**d) ID remapping is error-prone.** `update_scope_array()` walks all records and manually checks `isinstance` for types that have cross-references (`HttpEndpoint.web_path_id`, `HttpEndpointData.domain_id`, `HttpEndpointData.screenshot_id`). If a new record type with a foreign-key-style reference is added and this function isn't updated, silent data corruption occurs.

**Recommendation**:
- Use **dataclasses** (or Pydantic/attrs) with a type registry. Each record class declares its fields with types, and serialization/deserialization is generated automatically. A `ForeignKey` field annotation could drive the ID remapping generically.
- Define a shared schema (e.g., JSON Schema or protobuf) for the client-server contract. This catches breaking changes early.
- Eliminate the write-to-disk-then-re-read cycle. After import, update scope directly from the in-memory objects.

---

## 3. ScanData: A God Object

`ScanData` maintains **20+ dictionaries** as cross-referencing indices:

```python
host_map, host_ip_id_map, port_map, port_host_map,
domain_map, domain_name_map, domain_host_id_map,
http_endpoint_map, http_endpoint_port_id_map,
http_endpoint_data_map, endpoint_data_endpoint_id_map,
certificate_map, certificate_port_id_map,
vulnerability_map, screenshot_map, screenshot_hash_id_map,
web_component_map, component_port_id_map,
collection_module_map, host_port_obj_map, path_hash_id_map, ...
```

Every time a record is added, multiple maps must be updated in sync. The `_process_data()` method is ~100 lines of `isinstance` branching that manually inserts into the correct maps. The `update()` method mirrors this logic. These invariants are easy to break and have no validation.

**Recommendation**: Replace the manually-synchronized dictionaries with a lightweight in-memory relational store or at minimum a single indexed collection class. Each record type would declare its indexed fields, and the store maintains indices automatically. This also makes it trivial to add new record types without touching `_process_data()`.

---

## 4. Tool Wrappers: ~80% Boilerplate

Every tool file (masscan, nmap, httpx, nuclei, feroxbuster, shodan, etc.) repeats the same pattern:

1. A `WaluigiTool` subclass with name/scan_order/collector_type config
2. A static `scan_func` that calls `luigi.build([ToolScan(...)])`
3. A static `import_func` that calls `luigi.build([ImportToolOutput(...)])`
4. A `ToolScan` Luigi task with `output()` boilerplate and `run()` that builds a command and calls `process_wrapper()`
5. An `ImportToolOutput` task that calls `parse_X_output()` then `self.import_results()`

The only **unique** code per tool is:
- How to extract targets from `ScanData` (~10-20 lines)
- How to build the command-line arguments (~10-30 lines)
- How to parse the output format (~50-200 lines)

**Recommendation**: Create a declarative `ToolSpec` base class:

```python
class MasscanSpec(ToolSpec):
    name = "masscan"
    scan_order = 2
    collector_type = CollectorType.ACTIVE

    def build_commands(self, scan_data: ScanData) -> List[Command]:
        # Only the unique logic
        ...

    def parse_output(self, output_path: str, tool_instance_id: str) -> List[Record]:
        # Only the unique logic
        ...
```

The framework handles execution, process management, import, and scope update generically. This cuts each tool file by 60-70%.

---

## 5. Server Communication: Tightly Coupled

`ReconManager` mixes three concerns into one 1600+ line class:
- **HTTP client** (session management, encryption, request/response handling)
- **Scan orchestration** (polling, tool registration, scan lifecycle)
- **Data model management** (scope updates, ID remapping)

The encrypted API layer hard-codes `requests.post()` calls with `verify=False` throughout. Every endpoint duplicates the encrypt → POST → check status → decrypt pattern. There's no retry logic beyond session key refresh, and no rate limiting.

**Recommendation**: Extract a thin `ApiClient` class that handles encryption, auth, and HTTP transport. The `ReconManager` becomes a high-level orchestrator that calls `api.import_data(payload)` without knowing about encryption or HTTP details. This also makes testing possible — the current design is untestable without a live server.

---

## 6. Process Management: Accumulates Resources

`ScheduledScan.register_tool_executor()` stores process handles and futures in a map, but cancelled/completed entries are only partially cleaned. The `kill_scan_processes()` method sends `SIGKILL` but doesn't always remove the executor from the map. Over long-running collector sessions with many scans, this leaks memory.

The `process_wrapper()` in `scan_utils.py` uses `Popen` with a PID callback, but the callback registration pattern (via `functools.partial`) means the caller must coordinate between the future and the PID callback — two separate tracking mechanisms for the same process.

**Recommendation**: Unify process tracking into a single `ProcessHandle` object that wraps the future and PID together, with automatic cleanup on completion.

---

## 7. Additional Issues

| Issue | Detail |
|-------|--------|
| **SimpleNamespace for server data** | `get_scheduled_scans()` deserializes JSON into `SimpleNamespace` — no type safety, no validation, no IDE support. Unknown fields silently become attributes. |
| **Session key on disk** | The AES session key is cached as a hex string in `./session`. Any process with read access to the working directory can decrypt all traffic. |
| **`verify=False` everywhere** | All HTTPS calls disable certificate verification. This is flagged but never addressed. |
| **No backpressure** | If the server queues many scans, the collector spawns unbounded threads. There's no limit on concurrent scans. |
| **Wordlist sync** | Wordlists are downloaded per-scan by hash comparison. Large wordlists are re-downloaded on every scan if the hash changes, with no incremental update. |

---

## Summary of Recommended Changes (Priority Order)

1. **Drop Luigi** — Replace with direct function calls. Biggest complexity-to-value ratio improvement.
2. **Declarative tool specs** — Collapse boilerplate into a base class; tools only define command-building and output-parsing.
3. **Typed serialization** — Use dataclasses/Pydantic with a type registry and automatic ID remapping. Eliminate the manual `isinstance` chains.
4. **Extract ApiClient** — Separate transport/encryption from orchestration. Enable testing.
5. **Simplify ScanData** — Replace 20+ manually-synced dicts with an auto-indexed record store.
6. **Fix resource management** — Unified process handles, bounded concurrency, memory cleanup.
