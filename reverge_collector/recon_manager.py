"""
reverge_collector Reconnaissance Manager Module

This module provides the core scanning orchestration and management functionality
for the reverge_collector security scanning framework. It handles the complete lifecycle
of security scans including scheduling, execution, monitoring, and result
collection across multiple scanning tools and targets.

The module serves as the central coordinator that:
- Manages scheduled security scans and their execution workflows
- Orchestrates multiple scanning tools with proper sequencing and dependencies
- Handles secure communication with the backend management server
- Provides thread-safe execution of concurrent scanning operations
- Manages tool registration, configuration, and lifecycle
- Handles encrypted data transmission and session management
- Provides comprehensive error handling and recovery mechanisms

Key Components:
- ReconManager: Main class for managing scans and server communication
- ScheduledScan: Represents individual scan configurations and state
- ScheduledScanThread: Thread-based scan executor with polling capabilities
- SessionException: Custom exception for authentication and session issues
- ScanNotFoundException: Custom exception for when scans are not found on server
- ScanStatus/CollectionToolStatus: Enumerations for tracking scan states

The architecture supports:
- Multi-threaded scanning with proper resource management
- Secure encrypted communication using AES and RSA encryption
- Dynamic tool discovery, registration, and configuration
- Real-time scan monitoring and status reporting
- Robust error handling with automatic retry mechanisms
- Network interface discovery and management
- Wordlist management and distribution
- Scan result collection and aggregation

Classes:
    SessionException: Custom exception for session management failures
    ScanNotFoundException: Custom exception for scan not found errors (404)
    ScanStatus: Enumeration of possible scan states
    CollectionToolStatus: Enumeration of tool execution states
    ScheduledScan: Individual scan configuration and execution context
    ScheduledScanThread: Thread-based scan executor with polling capabilities
    ReconManager: Central scan orchestration and server communication manager

Functions:
    tool_order_cmp: Comparison function for tool execution ordering
    encrypt_data: AES encryption utility for secure data transmission
    get_recon_manager: Singleton factory for ReconManager instances

Constants:
    custom_user_agent (str): HTTP User-Agent string for web requests
    recon_mgr_inst: Global singleton instance of ReconManager
"""

import logging
import threading
import time
import traceback
from collections import OrderedDict
from functools import cmp_to_key, partial
from threading import Event, Thread
from typing import Any, Dict, List, Optional, Tuple

import netifaces
import requests

from reverge_collector import data_model, scan_cleanup
from reverge_collector.api_client import ApiClient

# Global Configuration: Disable SSL warnings for target sites with SSL issues
requests.packages.urllib3.disable_warnings()

# Global singleton instance of ReconManager
recon_mgr_inst: Optional['ReconManager'] = None


class SessionException(Exception):
    """
    Custom exception for session management and authentication failures.

    This exception is raised when there are issues with:
    - Session token retrieval or validation
    - Authentication with the backend server
    - Session key encryption/decryption failures
    - Connection establishment problems

    Attributes:
        message (str): Descriptive error message explaining the session failure

    Example:
        >>> try:
        ...     manager = ReconManager(token, url)
        ... except SessionException as e:
        ...     print(f"Session failed: {e}")

    Note:
        This exception indicates a need to refresh authentication or
        check connectivity with the management server.
    """

    def __init__(self, message: str = 'Unable to get session token') -> None:
        """
        Initialize SessionException with error message.

        Args:
            message (str): Error message describing the session failure.
                          Defaults to "Unable to get session token"

        Example:
            >>> raise SessionException("Session expired")
        """
        super().__init__(message)


class ScanNotFoundException(Exception):
    """
    Custom exception for when a scan is not found on the server.

    This exception is raised when attempting to update or retrieve a scan
    that no longer exists on the management server (404 response).

    Attributes:
        message (str): Descriptive error message explaining the scan not found

    Example:
        >>> try:
        ...     manager.update_scan_status(scan_id, status)
        ... except ScanNotFoundException as e:
        ...     print(f"Scan not found: {e}")

    Note:
        This exception indicates the scan has been deleted from the server
        and should be removed from local tracking.
    """

    def __init__(self, message: str = 'Scan not found on server') -> None:
        """
        Initialize ScanNotFoundException with error message.

        Args:
            message (str): Error message describing the scan not found error.
                          Defaults to "Scan not found on server"

        Example:
            >>> raise ScanNotFoundException("Scan ID 123 not found")
        """
        super().__init__(message)


class _LaunchpointSwitchError(Exception):
    """Internal signal that a batch could not reach a usable network.

    Raised inside ``_process_job_batch_with_slot`` when the launchpoint switch
    (to the extender or the target) fails, so the whole batch is reported as
    ERROR rather than run against the wrong network. Not part of the public API.
    """


def tool_order_cmp(x: Any, y: Any) -> int:
    """
    Comparison function for ordering collection tools by scan execution priority.

    This function determines the execution order of scanning tools based on their
    scan_order attribute. Tools with lower scan_order values are executed first,
    enabling proper sequencing of dependencies (e.g., port scanning before service
    enumeration).

    Args:
        x (Any): First collection tool object with collection_tool.scan_order attribute
        y (Any): Second collection tool object with collection_tool.scan_order attribute

    Returns:
        int: Comparison result for sorting:
            -1: x should be executed before y
             0: x and y have equal priority
             1: x should be executed after y

    Example:
        >>> tools = [tool1, tool2, tool3]
        >>> sorted_tools = sorted(tools, key=cmp_to_key(tool_order_cmp))

    Note:
        - Tools with scan_order=None are given highest priority (executed first)
        - Used with cmp_to_key() for Python 3 sorting compatibility
        - Essential for maintaining proper scanning workflow dependencies
    """
    # Tools without scan_order get highest priority (executed first)
    if x.collection_tool.scan_order is None:
        return -1

    if y.collection_tool.scan_order is None:
        return 1

    # Compare scan_order values for execution priority
    if x.collection_tool.scan_order > y.collection_tool.scan_order:
        return 1
    elif x.collection_tool.scan_order < y.collection_tool.scan_order:
        return -1
    else:
        return 0


class ScheduledScanThread(threading.Thread):
    """
    Thread-based executor for managing scheduled security scans with polling capabilities.

    This class extends threading.Thread to provide a dedicated execution context
    for security scanning operations. It implements a polling mechanism to
    continuously check for new scans, manage their execution, and handle
    cancellation requests from the management server.

    Key features:
    - Continuous polling for scheduled scans from the management server
    - Concurrent execution of multiple scans with proper resource management
    - Dynamic configuration updates from the server (poll intervals, etc.)
    - Scan cancellation and process termination capabilities
    - Real-time log collection and transmission to the server
    - Connection management with automatic retry logic
    - Luigi task failure handling and error reporting

    Attributes:
        failed_task_exception (Tuple): Instance variable holding task failures for error reporting
        _is_running (bool): Thread execution state flag
        _daemon (bool): Daemon thread flag for background execution
        _enabled (bool): Enable/disable scan polling
        recon_manager (ReconManager): Manager for server communication
        connection_manager (Optional): Connection management instance
        exit_event (Event): Thread synchronization for graceful shutdown
        checkin_interval (int): Polling interval in seconds (default: 30)
        scan_thread_lock (threading.Lock): Thread safety for scan operations
        log_queue (Optional[queue.Queue]): Queue for log message collection
        scheduled_scan_map (Dict): Map of active scheduled scans

    Example:
        >>> thread = ScheduledScanThread(recon_manager, connection_manager)
        >>> thread.start()
        >>> thread.toggle_poller()  # Enable/disable scanning

    Note:
        - Runs as a daemon thread for automatic cleanup on program exit
        - Implements Luigi event handler for task failure capture
        - Supports graceful shutdown via stop() method
    """

    def __init__(
        self, recon_manager: 'ReconManager', connection_manager: Optional[Any] = None
    ) -> None:
        """
        Initialize ScheduledScanThread with required managers and configuration.

        Args:
            recon_manager (ReconManager): Manager for server communication and scan operations
            connection_manager (Optional[Any]): Optional connection manager for target communication

        Example:
            >>> manager = ReconManager(token, url)
            >>> thread = ScheduledScanThread(manager)
            >>> thread.start()
        """
        threading.Thread.__init__(self)
        self._is_running = False
        self._daemon = True
        self._enabled = True
        self.recon_manager = recon_manager
        self.connection_manager = connection_manager
        self.exit_event = Event()
        self.checkin_interval = 30  # Default polling interval in seconds
        self.scan_thread_lock = threading.Lock()
        self.log_queue: Optional[Any] = None
        self.scheduled_scan_map: Dict[str, data_model.ScheduledScan] = {}
        # Per-instance variable to hold task failures (avoids cross-thread race)
        self.failed_task_exception: Optional[Tuple[Any, Exception]] = None
        # Jobs whose run_job succeeded but whose status POST failed (server
        # down / 5xx).  Retried on every subsequent poll iteration.
        # Maps job_id -> {"status": int, "result": dict|None, "err_msg": str|None}
        self.pending_job_completions: Dict[str, dict] = {}

        # --- Target-affinity gate ------------------------------------------
        # The launchpoint (single shared Synack browser target) can only point
        # at one target at a time.  This gate lets same-target jobs/scans run
        # concurrently while preventing a different target from switching the
        # launchpoint out from under in-flight work.
        #   _active_target_id        — the target currently checked out (or None)
        #   _active_worker_count     — in-flight workers on that target
        #   _active_target_reachable — set True by the switcher once it has
        #                              connected to the target and confirmed the
        #                              reverge server is reachable from it; peers
        #                              are only admitted once this is True
        self._target_state_lock = threading.Lock()
        self._active_target_id: Optional[str] = None
        self._active_worker_count = 0
        self._active_target_reachable = False
        # After a target switch the SSH tunnel comes up asynchronously, so the
        # switcher polls is_server_reachable a few times before deciding whether
        # the target is reachable (and therefore whether peers may join).  Tests
        # set the delay to 0 to keep the suite fast.
        self._target_reachable_confirm_attempts = 3
        self._target_reachable_confirm_delay = 1.0

    def _admit_work(self, target_id: Optional[str]) -> Optional[str]:
        """Decide whether to dispatch a unit of work for ``target_id`` now.

        Returns:
            ``'switch'`` — admitted; this worker owns the target and must
                connect to it (it is the first/only worker on it).
            ``'join'`` — admitted; the same target is already active and
                confirmed reachable, so this worker runs as a concurrent peer
                without touching the launchpoint.
            ``None`` — defer; a different target is active, or the same target
                is not yet confirmed reachable.  The item is left undispatched
                and re-evaluated on the next poll.
        """
        with self._target_state_lock:
            if self._active_worker_count == 0:
                self._active_target_id = target_id
                self._active_worker_count = 1
                self._active_target_reachable = False
                return 'switch'
            if self._active_target_id == target_id and self._active_target_reachable:
                self._active_worker_count += 1
                return 'join'
            return None

    def _finish_work(self) -> None:
        """Release this worker's slot in the affinity gate.

        Resets the active target once the last in-flight worker drains so the
        next poll can switch the launchpoint to a different target.
        """
        with self._target_state_lock:
            if self._active_worker_count > 0:
                self._active_worker_count -= 1
            if self._active_worker_count == 0:
                self._active_target_id = None
                self._active_target_reachable = False

    def _mark_target_reachable(self, reachable: bool) -> None:
        """Record whether the active target can reach the server.

        Called by the switcher after it connects to the target.  Once ``True``,
        same-target peers may be admitted to run concurrently.
        """
        with self._target_state_lock:
            self._active_target_reachable = reachable

    def _confirm_active_target_reachable(self, cm: Optional[Any]) -> bool:
        """Probe the freshly-connected target for server reachability and record it.

        The SSH tunnel is brought up from the target asynchronously (non-blocking
        connect_ssh), so this polls a few times to give it a window to come up
        before deciding.  When reachable, same-target peers may join and run
        concurrently; otherwise work on this target stays serial.
        """
        reachable = False
        attempts = max(1, self._target_reachable_confirm_attempts)
        for i in range(attempts):
            if self._server_reachable(cm):
                reachable = True
                break
            if i < attempts - 1 and self._target_reachable_confirm_delay > 0:
                time.sleep(self._target_reachable_confirm_delay)
        self._mark_target_reachable(reachable)
        return reachable

    def _try_begin_launchpoint_switch(self) -> bool:
        """Atomically decide whether this worker may switch the launchpoint.

        A switch (connect_to_extender) is only safe when this worker is the sole
        holder of the active target — otherwise it would yank the network out
        from under concurrent same-target peers.

        Crucially, the sole-holder check and closing the peer gate happen under
        the same lock: on success the reachable flag is cleared so the poll loop
        cannot admit a new peer between this check and the switch (which would
        otherwise leave that peer running on the wrong network once we switch).
        Returns ``True`` only when the caller may switch; ``False`` leaves the
        gate untouched so peers keep running and being admitted.
        """
        with self._target_state_lock:
            if self._active_worker_count <= 1:
                self._active_target_reachable = False
                return True
            return False

    def _no_workers_in_flight(self) -> bool:
        """Whether no worker currently owns a target.

        Used by the poll loop (which is not itself a worker) before it switches
        the launchpoint back to the extender — doing so while any worker is
        mid-turn would break that work.
        """
        with self._target_state_lock:
            return self._active_worker_count == 0

    def _server_reachable(self, cm: Optional[Any]) -> bool:
        """Whether the reverge server is reachable over the *current* connection.

        Probed by the worker threads *after* connecting to the target, so a
        ``True`` result means the active target VPN can still reach the server
        (the SSH tunnel survived the switch to the target). The caller then
        reports results directly and skips the costly launchpoint switch back to
        the extender.

        This must never be used to decide whether to connect to the target —
        connecting to the target is unconditional. It only gates the
        *return trip* to the extender for server communication.

        Delegates to ``cm.is_server_reachable()``. Safe default ``False`` (do the
        extender round-trip) when there is no connection manager, it exposes no
        such probe, the probe raises, or returns anything other than the literal
        ``True`` (guards against truthy-but-not-True values such as a bare mock).
        """
        if cm is None:
            return False
        probe = getattr(cm, 'is_server_reachable', None)
        if not callable(probe):
            return False
        try:
            return probe() is True
        except Exception:
            return False

    def _ensure_server_reachable(self, cm: Optional[Any]) -> bool:
        """Ensure the reverge server is reachable for server communication.

        When the server is already reachable over the current connection (e.g.
        the target VPN still has internet) we stay put and avoid the expensive
        launchpoint switch back to the extender. Otherwise we switch the
        launchpoint back to the extender.

        Returns:
            bool: ``True`` when the server should be reachable afterwards (it
            already was, there is no connection manager, or
            ``connect_to_extender()`` did not explicitly fail). ``False`` only
            when the extender switch returned ``False``.
        """
        if cm is None:
            return True
        if self._server_reachable(cm):
            return True
        # Not reachable: switching the launchpoint back to the extender is only
        # safe when this worker is the sole holder of the active target.  With
        # concurrent same-target peers in flight the switch would yank the
        # network out from under them, so report failure instead and let the
        # caller queue the result for retry.  The claim also atomically closes
        # the peer gate so the poll loop can't admit a new peer mid-switch.
        if not self._try_begin_launchpoint_switch():
            return False
        switched = cm.connect_to_extender() is not False
        # Launchpoint moved back to the extender: drop the stale manager pool.
        self.recon_manager.reset_api_pool()
        return switched

    def _process_scan_obj_with_slot(
        self, scheduled_scan_obj: data_model.ScheduledScan, mode: str = 'switch'
    ) -> None:
        """Run scan processing in a dedicated thread."""
        self.process_scan_obj(scheduled_scan_obj, mode=mode)

    def _flush_pending_job_completions(self) -> None:
        """Retry reporting jobs that completed locally but failed to report.

        All pending completions are flushed in a single batched request, so a
        backlog costs one round-trip (and one retry ladder) rather than one per
        job. On failure the whole backlog stays queued for the next poll.
        """
        with self.scan_thread_lock:
            pending = dict(self.pending_job_completions)

        if not pending:
            return

        entries = [self._pending_to_entry(jid, p) for jid, p in pending.items()]
        try:
            self.recon_manager.update_jobs_status_batch(entries)
        except Exception:
            logging.getLogger(__name__).warning(
                'Pending job flush (%d job(s)) failed; will retry next poll', len(pending)
            )
            return

        logging.getLogger(__name__).debug('Flushed %d pending job result(s)', len(pending))
        with self.scan_thread_lock:
            for job_id in pending:
                self.pending_job_completions.pop(job_id, None)
                self.scheduled_scan_map.pop(job_id, None)

    def _bucket_jobs_by_target(self, items: List[Any]) -> 'OrderedDict[str, List[Any]]':
        """Group not-yet-dispatched CollectorJob items by ``target_id``.

        Only items whose ``_type`` is ``'job'`` and that are not already
        in-flight (``scheduled_scan_map``) are bucketed; scans are left for the
        scan-dispatch path.  Insertion order is preserved so the poll loop
        admits targets in the order the server returned them.

        Batching same-target jobs into one worker means a single launchpoint
        switch (and one affinity slot) covers the whole group instead of one
        switch per job.
        """
        buckets: OrderedDict[str, List[Any]] = OrderedDict()
        for item in items:
            if getattr(item, '_type', 'scan') != 'job':
                continue
            if item.id in self.scheduled_scan_map:
                continue
            buckets.setdefault(item.target_id, []).append(item)
        return buckets

    def _dispatch_job_batches(self, items: List[Any]) -> None:
        """Admit and dispatch not-yet-running CollectorJobs as per-target batches.

        Caller holds ``scan_thread_lock``.  Jobs are bucketed by target and each
        admitted target gets ONE worker thread that runs all its queued jobs
        under a single launchpoint switch (and a single affinity slot).  Targets
        the affinity gate defers (a different target is active, or this one isn't
        confirmed reachable yet) are simply left for the next poll.
        """
        for target_id, target_jobs in self._bucket_jobs_by_target(items).items():
            mode = self._admit_work(target_id)
            if mode is None:
                continue
            for job_item in target_jobs:
                self.scheduled_scan_map[job_item.id] = job_item
            Thread(
                target=partial(self._process_job_batch_with_slot, list(target_jobs), mode)
            ).start()

    @staticmethod
    def _pending_to_entry(job_id: str, pending: Dict[str, Any]) -> Dict[str, Any]:
        """Build a wire entry from a ``{status, result, err_msg}`` completion."""
        entry: Dict[str, Any] = {'job_id': job_id, 'status': pending['status']}
        if pending.get('err_msg'):
            entry['status_message'] = pending['err_msg'][:2048]
        if pending.get('result') is not None:
            entry['result'] = pending['result']
        return entry

    def _report_job_batch(self, batch: Dict[str, Dict[str, Any]]) -> set:
        """Report a whole batch of terminal job statuses in one request.

        ``batch`` maps job_id -> ``{status, result, err_msg}``. Collapsing the
        reports into a single POST means one network round-trip (and one retry
        ladder on failure) instead of one per job.

        Returns the set of job_ids that must be queued for retry (the report
        POST failed) — the caller must NOT pop those from ``scheduled_scan_map``
        or the poll loop would re-run the already-executed, side-effecting
        commands.  On success returns an empty set.
        """
        if not batch:
            return set()
        entries = [self._pending_to_entry(jid, p) for jid, p in batch.items()]
        try:
            self.recon_manager.update_jobs_status_batch(entries)
            return set()
        except Exception:
            logging.getLogger(__name__).warning(
                'Batch status POST for %d job(s) failed; will retry on next poll',
                len(batch),
            )
            with self.scan_thread_lock:
                for jid, p in batch.items():
                    self.pending_job_completions[jid] = p
            return set(batch.keys())

    def _process_job_with_slot(self, job_item, mode: str = 'switch') -> None:
        """Execute a single CollectorJob (batch-of-one) and report the result."""
        self._process_job_batch_with_slot([job_item], mode)

    def _process_job_batch_with_slot(self, jobs: List[Any], mode: str = 'switch') -> None:
        """Execute a batch of same-target CollectorJobs under one launchpoint switch.

        All ``jobs`` share a ``target_id``.  ``mode`` comes from the
        target-affinity gate:
          - ``'switch'`` — this worker owns the target: it takes the connection
            lock, switches the launchpoint to the target once, runs every job,
            switches back, and reports.  One affinity slot covers the batch.
          - ``'join'`` — a concurrent same-target peer: the launchpoint is
            already committed to the target, so it never takes the lock or
            touches the launchpoint; it just runs its jobs and reports.

        A single job failing (connect/run) is reported as that job's ERROR and
        never aborts its siblings.  A launchpoint-switch failure fails the whole
        batch (no target to run on).
        """
        from reverge_collector.job_executor import run_job

        if not jobs:
            return

        is_peer = mode == 'join'
        target_id = jobs[0].target_id
        # Job ids queued for retry (status POST failed): their scheduled_scan_map
        # entry must survive so the poll loop won't re-run the side-effecting
        # command while the retry is pending.
        queued_for_retry: set = set()
        cm = self.connection_manager
        try:
            # Only the switcher serializes launchpoint use behind the connection
            # lock; peers ride the already-committed target connection.
            if cm and not is_peer:
                cm.get_connection_lock()

            # Ensure the server is reachable before any server communication.
            # A failure here means we never reached a usable network, so the
            # whole batch errors out.
            if not is_peer and not self._ensure_server_reachable(cm):
                raise _LaunchpointSwitchError('Failed connecting to extender')

            # RUNNING for every job (best-effort, still on the extender/server).
            for job_item in jobs:
                try:
                    self.recon_manager.update_job_status(
                        job_item.id, data_model.ScanStatus.RUNNING.value
                    )
                except Exception:
                    logging.getLogger(__name__).warning(
                        'Job %s: failed to set RUNNING status; proceeding anyway',
                        job_item.id,
                    )

            results: Dict[str, Any] = {}
            run_errors: Dict[str, str] = {}
            try:
                # Switch to the target once for the whole batch, then confirm
                # reachability so same-target peers may join.  Peers skip this.
                if not is_peer:
                    if cm and cm.connect_to_target(target_id) == False:
                        raise _LaunchpointSwitchError('Failed connecting to target %s' % target_id)
                    if cm:
                        # Launchpoint moved to the target: pooled manager
                        # connections are stale for the new route.
                        self.recon_manager.reset_api_pool()
                    self._confirm_active_target_reachable(cm)

                # Run every job on the committed target.  Per-job failures are
                # captured so one bad job can't abort the rest of the batch.
                for job_item in jobs:
                    try:
                        results[job_item.id] = run_job(job_item.job_type, job_item.args)
                    except Exception as e:
                        run_errors[job_item.id] = str(e)
                        logging.getLogger(__name__).error('Job %s failed: %s', job_item.id, e)
                        logging.getLogger(__name__).debug(traceback.format_exc())

            finally:
                # After target work, make sure the server is reachable to report
                # results. When the target VPN can still reach the server we
                # report directly over that tunnel and skip the costly switch
                # back to the extender; otherwise (and only when sole holder) we
                # switch back. Peers never switch the launchpoint.
                if not is_peer:
                    self._ensure_server_reachable(cm)

            # Build each job's terminal status and report the whole batch in a
            # single request (one round-trip / one retry ladder for the group).
            batch: Dict[str, Dict[str, Any]] = {}
            for job_item in jobs:
                if job_item.id in run_errors:
                    batch[job_item.id] = {
                        'status': data_model.ScanStatus.ERROR.value,
                        'result': None,
                        'err_msg': run_errors[job_item.id],
                    }
                else:
                    result = results.get(job_item.id)
                    batch[job_item.id] = {
                        'status': data_model.ScanStatus.COMPLETED.value,
                        'result': result,
                        'err_msg': None,
                    }
            queued_for_retry |= self._report_job_batch(batch)

        except _LaunchpointSwitchError as e:
            # No usable target/network for the batch: error out every job.
            err_msg = str(e)
            logging.getLogger(__name__).error('Job batch on target %s failed: %s', target_id, e)
            batch = {
                job_item.id: {
                    'status': data_model.ScanStatus.ERROR.value,
                    'result': None,
                    'err_msg': err_msg,
                }
                for job_item in jobs
            }
            queued_for_retry |= self._report_job_batch(batch)
        finally:
            if cm and not is_peer:
                cm.free_connection_lock()
            # Release this worker's single slot in the affinity gate so the
            # target can drain and a different target can take the launchpoint.
            self._finish_work()
            with self.scan_thread_lock:
                for job_item in jobs:
                    if job_item.id not in queued_for_retry:
                        self.scheduled_scan_map.pop(job_item.id, None)

    def catch_failure(self, task: Any, exception: Exception) -> None:
        """Capture tool task failures for inclusion in status updates."""
        self.failed_task_exception = (task, exception)

    def toggle_poller(self) -> None:
        """
        Toggle the scan polling mechanism on/off.

        This method enables or disables the scanning polling loop, allowing
        for runtime control of scan execution without stopping the thread.

        Example:
            >>> thread.toggle_poller()  # Disable if enabled, enable if disabled
            >>> # Check logs for confirmation message

        Note:
            - Thread continues running but skips scan polling when disabled
            - Useful for maintenance or debugging without full thread restart
        """
        if self._enabled:
            self._enabled = False
            logging.getLogger(__name__).debug('Scan poller disabled.')
        else:
            self._enabled = True
            logging.getLogger(__name__).debug('Scan poller enabled.')

    def execute_scan_jobs(
        self, scheduled_scan_obj: data_model.ScheduledScan, mode: str = 'switch'
    ) -> Optional[str]:
        """
        Execute all collection tools for a scheduled scan in proper order.

        This method orchestrates the execution of multiple scanning tools within
        a scan, handling proper sequencing, connection management, and error
        recovery. It manages the complete tool lifecycle from initialization
        through result import.

        The execution workflow:
        1. Configure connection target for the scan
        2. Sort tools by execution order (scan_order attribute)
        3. Establish connection to extender if required
        4. Execute each enabled tool in sequence
        5. Handle cancellation requests during execution
        6. Import results from completed tools
        7. Perform cleanup operations

        Args:
            scheduled_scan_obj (ScheduledScan): Scan object containing tool configuration
                                              and execution context

        Returns:
            Optional[str]: Error message if execution failed, None if successful

        Example:
            >>> error = thread.execute_scan_jobs(scan_obj)
            >>> if error:
            ...     print(f"Scan failed: {error}")
            ... else:
            ...     print("Scan completed successfully")

        Note:
            - Tools are executed in order based on scan_order attribute
            - Supports real-time cancellation through server status checks
            - Handles both active scanning tools (tool_type=2) and passive tools
            - Automatically performs cleanup on successful completion
        """
        err_msg = None
        is_peer = mode == 'join'
        # Configure connection target for this scan
        target_id = scheduled_scan_obj.target_id
        cm = self.connection_manager

        # Sort tools by execution order for proper dependency handling
        collection_tools = scheduled_scan_obj.collection_tool_map.values()
        sorted_list = sorted(collection_tools, key=cmp_to_key(tool_order_cmp))

        # Ensure the server is reachable for scan status monitoring. No-op when
        # the current connection already reaches the server; otherwise switches
        # the launchpoint to the extender. Peers ride the already-reachable
        # target connection and never switch the launchpoint.
        if not is_peer and not self._ensure_server_reachable(cm):
            err_msg = 'Failed connecting to extender'
            logging.getLogger(__name__).error(err_msg)
            return err_msg

        ret_status = None
        for collection_tool_inst in sorted_list:
            # Execute each tool with proper error handling
            try:
                tool_obj = collection_tool_inst.collection_tool

                # Skip disabled tools or tools without scan order
                if tool_obj.scan_order == None or collection_tool_inst.enabled == 0:
                    logging.getLogger(__name__).debug(
                        'Skipping tool %s due to disabled status or missing scan order',
                        tool_obj.name,
                    )
                    continue

                # Set initial status after continue checks
                ret_status = data_model.CollectionToolStatus.RUNNING.value

                # Apply argument overrides if specified
                if collection_tool_inst.args_override:
                    tool_obj.args = collection_tool_inst.args_override

                # Configure current tool for scan context
                scheduled_scan_obj.current_tool = tool_obj
                scheduled_scan_obj.current_tool_instance_id = collection_tool_inst.id
                scheduled_scan_obj.current_tool_api_key = collection_tool_inst.api_key

                # Check for scan cancellation from server
                scan_status = self.recon_manager.get_scan_status(scheduled_scan_obj.scan_id)
                if (
                    scan_status is None
                    or scan_status.scan_status == data_model.ScanStatus.CANCELLED.value
                ):
                    err_msg = "Scan cancelled or doesn't exist"
                    logging.getLogger(__name__).debug(err_msg)
                    # Perform cleanup for cancelled scan
                    scan_cleanup.scan_cleanup_func(scheduled_scan_obj.id)
                    return err_msg

                # Check for individual tool cancellation
                cancelled_tool_ids = scan_status.cancelled_tool_ids
                if collection_tool_inst.id in cancelled_tool_ids:
                    logging.getLogger(__name__).debug(
                        """Tool %s cancelled before execution, skipping""" % tool_obj.name
                    )
                    continue

                # Update tool status to running
                scheduled_scan_obj.update_tool_status(
                    collection_tool_inst.id, data_model.CollectionToolStatus.RUNNING.value
                )

                try:
                    # Connect to target only for active scanning tools, and only
                    # as the switcher — a peer's launchpoint is already on the
                    # target. Once on it, the switcher confirms reachability so
                    # same-target peers may join.
                    if tool_obj.tool_type == 2 and not is_peer:
                        if cm and cm.connect_to_target(target_id) == False:
                            err_msg = 'Failed connecting to target'
                            logging.getLogger(__name__).error(err_msg)
                            return err_msg
                        if cm:
                            # Launchpoint moved to the target: drop the stale
                            # manager connection pool.
                            self.recon_manager.reset_api_pool()
                        self._confirm_active_target_reachable(cm)

                    # Execute the actual scanning function
                    try:
                        if self.recon_manager.scan_func(scheduled_scan_obj) == False:
                            err_msg = 'Scan function failed'
                            logging.getLogger(__name__).debug(err_msg)
                            ret_status = data_model.CollectionToolStatus.ERROR.value

                    except Exception as e:
                        err_msg = 'Error calling scan function: %s' % str(e)
                        logging.getLogger(__name__).error(err_msg)
                        logging.getLogger(__name__).debug(traceback.format_exc())
                        ret_status = data_model.CollectionToolStatus.ERROR.value

                    # Check for task failures
                    if self.failed_task_exception:
                        task_err = (
                            f'{self.failed_task_exception[0]}\n{self.failed_task_exception[1]}'
                        )
                        self.failed_task_exception = None
                        err_msg = task_err if not err_msg else f'{err_msg}\n{task_err}'

                finally:
                    # After scanning the target, ensure the server is reachable
                    # to import results. Reports directly over the target tunnel
                    # when reachable; otherwise (switcher only, sole holder)
                    # switches back to the extender. Peers never switch.
                    if not is_peer and not self._ensure_server_reachable(cm):
                        err_msg = 'Failed connecting to extender'
                        logging.getLogger(__name__).error(err_msg)
                        return err_msg

                # If scan failed, update status and stop tool loop
                if ret_status == data_model.CollectionToolStatus.ERROR.value:
                    scheduled_scan_obj.update_tool_status(
                        collection_tool_inst.id, ret_status, err_msg
                    )
                    break

                # Import scan results regardless of tool type
                import_err_msg = None
                try:
                    if self.recon_manager.import_func(scheduled_scan_obj) == False:
                        import_err_msg = 'Import function failed'
                        logging.getLogger(__name__).debug(import_err_msg)
                        ret_status = data_model.CollectionToolStatus.IMPORT_FAILED.value
                    else:
                        ret_status = data_model.CollectionToolStatus.COMPLETED.value
                except Exception as e:
                    import_err_msg = 'Error calling import function: %s' % str(e)
                    logging.getLogger(__name__).error(import_err_msg)
                    logging.getLogger(__name__).debug(traceback.format_exc())
                    ret_status = data_model.CollectionToolStatus.IMPORT_FAILED.value

                # Check for task failures from import
                if self.failed_task_exception:
                    task_err = f'{self.failed_task_exception[0]}\n{self.failed_task_exception[1]}'
                    self.failed_task_exception = None
                    import_err_msg = (
                        task_err if not import_err_msg else f'{import_err_msg}\n{task_err}'
                    )
                    ret_status = data_model.CollectionToolStatus.IMPORT_FAILED.value

                # Update tool status once after import
                scheduled_scan_obj.update_tool_status(
                    collection_tool_inst.id, ret_status, import_err_msg if import_err_msg else ''
                )

                if ret_status == data_model.CollectionToolStatus.IMPORT_FAILED.value:
                    # The scan phase completed but the server POST failed (e.g.
                    # server down / 500).  Flag the scan so the scheduler keeps
                    # it RUNNING for retry on the next polling iteration.
                    # Subsequent tools are intentionally skipped because they
                    # may depend on this tool's results being in scope.
                    scheduled_scan_obj.has_pending_imports = True
                    break

            except Exception:
                logging.getLogger(__name__).error('Error executing scan job')
                logging.getLogger(__name__).error(traceback.format_exc())
            finally:
                # Clean up current tool references
                scheduled_scan_obj.current_tool = None
                scheduled_scan_obj.current_tool_instance_id = None

        # Only archive/delete scan directory when all imports succeeded.
        # If has_pending_imports is set the output files (especially
        # tool_pre_import_json) must survive so the next polling iteration
        # can retry just the POST without re-running the scan.
        if not scheduled_scan_obj.has_pending_imports:
            scan_cleanup.scan_cleanup_func(scheduled_scan_obj.id)

        return err_msg

    def process_collector_settings(self, collector_settings: Dict[str, Any]) -> None:
        """
        Process and apply collector configuration settings from the server.

        This method handles dynamic configuration updates received from the
        management server, allowing runtime adjustment of collector behavior
        without requiring a restart.

        Args:
            collector_settings (Dict[str, Any]): Configuration dictionary from server
                                                containing settings to apply

        Example:
            >>> settings = {"poll_interval": 60}
            >>> thread.process_collector_settings(settings)

        Supported Settings:
            - poll_interval (int): Polling interval in seconds (1-3600 range)

        Note:
            - Settings are validated before application
            - Invalid settings are logged but don't stop execution
            - Poll interval changes take effect on next polling cycle
        """
        try:
            # Process poll interval configuration
            if 'poll_interval' in collector_settings:
                poll_interval = int(collector_settings['poll_interval'])
                # Validate poll interval range (1 second to 1 hour)
                if (
                    self.checkin_interval != poll_interval
                    and poll_interval > 0
                    and poll_interval < 3600
                ):
                    # Update the polling interval
                    self.checkin_interval = poll_interval
                    logging.getLogger(__name__).debug(
                        f'Updated poll interval to {poll_interval} seconds'
                    )

        except Exception as e:
            logging.getLogger(__name__).error('Error processing collector settings: %s' % str(e))
            logging.getLogger(__name__).debug(traceback.format_exc())

    def process_scan_obj(
        self, scheduled_scan_obj: data_model.ScheduledScan, mode: str = 'switch'
    ) -> None:
        """
        Process a single scheduled scan from creation to completion.

        This method handles the complete lifecycle of a scan including execution,
        status management, error handling, and cleanup. It's designed to run
        in a separate thread for concurrent scan processing.

        Args:
            scheduled_scan_obj (ScheduledScan): Scan object to process

        Example:
            >>> scan = ScheduledScan(thread, scan_config)
            >>> Thread(target=thread.process_scan_obj, args=(scan,)).start()

        Process Flow:
            1. Execute scan jobs with tool orchestration
            2. Handle connection management for result import
            3. Update scan status based on execution results
            4. Perform cleanup operations
            5. Remove scan from active scan map

        Note:
            - Runs in separate thread for non-blocking execution
            - Handles all exceptions to prevent thread termination
            - Ensures scan is removed from map regardless of outcome
        """
        # Initialize scan processing
        err_msg = None
        is_peer = mode == 'join'

        # Default to error status for safety
        scan_status = data_model.ScanStatus.ERROR.value
        cm = self.connection_manager
        try:
            # Only the switcher serializes launchpoint use behind the connection
            # lock; a same-target peer rides the already-committed connection.
            if cm and not is_peer:
                cm.get_connection_lock()

            err_msg = self.execute_scan_jobs(scheduled_scan_obj, mode=mode)

            # Ensure the server is reachable for status updates — reports over
            # the target tunnel when reachable, otherwise switches back to the
            # extender. Peers never switch the launchpoint.
            if not is_peer and not self._ensure_server_reachable(cm):
                logging.getLogger(__name__).error('Failed connecting to extender')
                return False

            if err_msg is None and not scheduled_scan_obj.has_pending_imports:
                # Scan completed successfully
                scan_status = data_model.ScanStatus.COMPLETED.value

                # Perform resource cleanup
                scheduled_scan_obj.cleanup()
            elif scheduled_scan_obj.has_pending_imports:
                # Scan phase succeeded but the server POST failed (e.g. server
                # down / 500).  Leave the scan RUNNING so the next polling
                # iteration picks it up and retries only the import step using
                # the cached tool_pre_import_json — no re-scanning needed.
                # Do NOT call cleanup() so wordlists and output files survive.
                scan_status = data_model.ScanStatus.RUNNING.value
                logging.getLogger(__name__).warning(
                    'Scan %s has pending imports; leaving RUNNING for retry on next poll iteration',
                    scheduled_scan_obj.id,
                )

        except Exception as e:
            logging.getLogger(__name__).error('Error executing scan job')
            logging.getLogger(__name__).debug(traceback.format_exc())
            if 'outage' in str(e):
                scan_status = data_model.ScanStatus.CANCELLED.value
        finally:
            try:
                # Ensure the server is reachable before the final status update
                # (no-op when already reachable from the target). Peers never
                # switch the launchpoint.
                if not is_peer:
                    self._ensure_server_reachable(cm)

                # Update final scan status on server
                scheduled_scan_obj.update_scan_status(scan_status)

            except ScanNotFoundException as e:
                # Scan was deleted from server, remove from local tracking
                logging.getLogger(__name__).warning(
                    f'Scan {scheduled_scan_obj.id} not found on server, removing from local map: {e}'
                )
                with self.scan_thread_lock:
                    if scheduled_scan_obj.id in self.scheduled_scan_map:
                        del self.scheduled_scan_map[scheduled_scan_obj.id]
            except Exception as e:
                logging.getLogger(__name__).debug(traceback.format_exc())
            finally:
                if cm and not is_peer:
                    cm.free_connection_lock()
                # Release this worker's slot in the affinity gate.
                self._finish_work()

        # Always remove the scan from the map when processing is done.
        # If the server wants a retry, it will return the scan again in
        # get_scheduled_scans() and a fresh thread will be spawned.
        with self.scan_thread_lock:
            if scheduled_scan_obj.id in self.scheduled_scan_map:
                del self.scheduled_scan_map[scheduled_scan_obj.id]

        return

    def run(self) -> None:
        """
        Main thread execution loop for continuous scan polling and management.

        This method implements the core polling loop that continuously checks
        for new scheduled scans, manages their execution, and handles cancellation
        requests. It runs until the thread is stopped via the stop() method.

        The polling loop:
        1. Wait for poll interval or exit event
        2. Acquire connection lock if using connection manager
        3. Collect and transmit log messages to server
        4. Poll server for collector settings updates
        5. Retrieve and process scheduled scans
        6. Handle scan cancellation requests
        7. Release connection lock and handle errors

        Example:
            >>> thread = ScheduledScanThread(manager)
            >>> thread.start()  # Calls run() in background thread

        Error Handling:
            - Connection errors trigger retry without stopping
            - Lock acquisition failures cause retry on next cycle
            - General exceptions are logged but don't stop polling
            - Proper resource cleanup in finally blocks

        Note:
            - Runs as daemon thread for automatic cleanup
            - Supports graceful shutdown via exit_event
            - Thread-safe operations with proper locking
        """
        if not self._is_running:
            # Validate recon manager availability
            recon_manager = self.recon_manager
            if recon_manager:
                # Set running flag and enter main loop
                self._is_running = True
                first_poll = True
                while self._is_running:
                    # Poll immediately on first iteration, then wait
                    if first_poll:
                        first_poll = False
                    else:
                        self.exit_event.wait(self.checkin_interval)

                    # Flush any pending job results first so HTTP retries never
                    # stall running jobs.
                    self._flush_pending_job_completions()

                    if self._enabled:
                        try:
                            # The poll loop does not hold the connection lock: it
                            # only talks to the server (HTTP over the current
                            # tunnel) and dispatches workers. Holding the lock here
                            # would block behind a long-running switcher and stop
                            # same-target peers from ever being dispatched. The
                            # target-affinity gate coordinates launchpoint use;
                            # the only launchpoint switch in this loop (the
                            # ConnectionError handler below) is guarded by
                            # _no_workers_in_flight().

                            # Collect log messages for transmission
                            result_str = None
                            result_list = []
                            if self.log_queue:
                                while not self.log_queue.empty() and len(result_list) < 100:
                                    result_list.append(self.log_queue.get())
                            if len(result_list) > 0:
                                result_str = '\n'.join(result_list)

                            # Poll server for collector settings updates
                            collector_settings = recon_manager.collector_poll(result_str)
                            if collector_settings:
                                self.process_collector_settings(collector_settings)

                            # Retry any job completions whose earlier POST failed.
                            # (handled above, outside the connection lock)

                            # Process scheduled scans and jobs with thread safety
                            with self.scan_thread_lock:
                                sched_scan_obj_arr = recon_manager.get_scheduled_scans()

                                # --- Collector Job dispatch ---
                                # Batch same-target jobs into one worker per
                                # target so a single launchpoint switch (and one
                                # affinity slot) covers the whole group instead
                                # of one switch per job.
                                self._dispatch_job_batches(sched_scan_obj_arr)

                                for sched_scan_obj in sched_scan_obj_arr:
                                    item_type = getattr(sched_scan_obj, '_type', 'scan')

                                    # Jobs were dispatched in per-target batches
                                    # above.
                                    if item_type == 'job':
                                        continue

                                    # --- Scan dispatch ---
                                    # Handle new scans
                                    if sched_scan_obj.id not in self.scheduled_scan_map:
                                        # Target-affinity gate: switch/join, or
                                        # defer (None) when a different target is
                                        # active or this one isn't yet confirmed
                                        # reachable. Deferred scans come back on
                                        # the next poll.
                                        mode = self._admit_work(sched_scan_obj.target_id)
                                        if mode is None:
                                            continue

                                        logging.getLogger(__name__).debug(
                                            'Processing new scan: %s', sched_scan_obj.id
                                        )

                                        # Create new scheduled scan instance
                                        scheduled_scan_obj = data_model.ScheduledScan(
                                            self, sched_scan_obj
                                        )
                                        self.scheduled_scan_map[sched_scan_obj.id] = (
                                            scheduled_scan_obj
                                        )

                                        # Start scan processing in separate thread
                                        Thread(
                                            target=partial(
                                                self._process_scan_obj_with_slot,
                                                scheduled_scan_obj,
                                                mode,
                                            )
                                        ).start()

                                    else:
                                        # Handle existing scans - check for cancellation
                                        scheduled_scan_obj = self.scheduled_scan_map[
                                            sched_scan_obj.id
                                        ]
                                        status_obj = self.recon_manager.get_scan_status(
                                            scheduled_scan_obj.scan_id
                                        )

                                        # Process scan cancellation
                                        if (
                                            status_obj is None
                                            or status_obj.scan_status
                                            == data_model.ScanStatus.CANCELLED.value
                                        ):
                                            logging.getLogger(__name__).debug('Scan cancelled')
                                            scheduled_scan_obj.kill_scan_processes()

                                            # Remove from the map
                                            del self.scheduled_scan_map[scheduled_scan_obj.id]

                                        else:
                                            # Process individual tool cancellation.
                                            # The server keeps listing cancelled
                                            # tool ids while the scan is RUNNING,
                                            # so only kill ones we haven't already
                                            # killed — otherwise we'd re-kill (and
                                            # re-log) the same dead tools every
                                            # poll iteration.
                                            cancelled_tool_ids = status_obj.cancelled_tool_ids
                                            new_tool_ids = [
                                                tid
                                                for tid in cancelled_tool_ids
                                                if tid not in scheduled_scan_obj.killed_tool_ids
                                            ]

                                            # Terminate newly-cancelled tools
                                            if len(new_tool_ids) > 0:
                                                logging.getLogger(__name__).debug(
                                                    'Killing cancelled tools'
                                                )
                                                scheduled_scan_obj.kill_scan_processes(new_tool_ids)
                                                scheduled_scan_obj.killed_tool_ids.update(
                                                    new_tool_ids
                                                )

                        except requests.exceptions.ConnectionError as e:
                            logging.getLogger(__name__).error('Unable to connect to server.')
                            # Only switch the launchpoint back to the extender when
                            # no worker is mid-turn on a target — otherwise we'd
                            # yank the network out from under in-flight work. If a
                            # target is active the poll just retries next cycle.
                            if self.connection_manager and self._no_workers_in_flight():
                                self.connection_manager.connect_to_extender()
                                # Launchpoint moved back to the extender: drop
                                # the stale manager connection pool.
                                self.recon_manager.reset_api_pool()
                        except Exception as e:
                            logging.getLogger(__name__).debug(traceback.format_exc())

    def stop(self, timeout: Optional[float] = None) -> None:
        """
        Stop the scan thread and signal graceful shutdown.

        This method signals the main polling loop to exit and allows for
        graceful shutdown of all scanning operations.

        Args:
            timeout (Optional[float]): Maximum time to wait for shutdown (unused)

        Example:
            >>> thread.stop()
            >>> thread.join()  # Wait for thread to finish

        Note:
            - Sets internal flags to stop the polling loop
            - Triggers exit_event to interrupt polling wait
            - Does not forcefully terminate running scans
        """
        # Signal thread to stop running
        self._is_running = False
        # Wake up thread from polling wait
        self.exit_event.set()


def get_recon_manager(token: str, manager_url: str) -> 'ReconManager':
    """
    Factory function to get or create a singleton ReconManager instance.

    This function implements the singleton pattern for ReconManager instances,
    ensuring only one manager exists per application instance. This prevents
    multiple authentication sessions and resource conflicts.

    Args:
        token (str): Authentication token for server communication
        manager_url (str): Base URL of the management server

    Returns:
        ReconManager: Singleton instance of the reconnaissance manager

    Example:
        >>> manager = get_recon_manager("auth-token-123", "https://server.com")
        >>> # Subsequent calls return the same instance
        >>> same_manager = get_recon_manager("different-token", "different-url")
        >>> assert manager is same_manager  # True

    Note:
        - First call creates the instance with provided parameters
        - Subsequent calls return the existing instance regardless of parameters
        - Global singleton pattern ensures consistent state across the application
    """
    global recon_mgr_inst
    if recon_mgr_inst is None:
        recon_mgr_inst = ReconManager(token, manager_url)
    # Register (or re-register) with the server.  Only does a network
    # call — tool modules are already loaded inside __init__.
    recon_mgr_inst.register_with_server()
    return recon_mgr_inst


class ReconManager:
    """
    Central manager for reconnaissance operations and server communication.

    This class serves as the primary interface between the reverge_collector scanning
    framework and the backend management server. It handles all aspects of
    scan orchestration, secure communication, tool management, and data
    exchange with the server infrastructure.

    Key responsibilities:
    - Secure session management with RSA/AES encryption
    - Tool discovery, registration, and lifecycle management
    - Network interface discovery and configuration
    - Scan execution orchestration and result collection
    - Real-time communication with management server
    - Data import/export operations with encryption
    - Error handling and session recovery

    The manager implements a comprehensive API for:
    - Authentication and session key exchange
    - Scheduled scan retrieval and management
    - Tool status monitoring and updates
    - Data import operations (ports, screenshots, scan results)
    - Network resource discovery (subnets, hosts, URLs)
    - Collector configuration and polling

    Attributes:
        token (str): Authentication token for server communication
        debug (bool): Debug mode flag for verbose logging
        manager_url (str): Base URL of the management server
        headers (Dict): HTTP headers including authentication
        session_key (bytes): AES session key for encrypted communication
        network_ifaces (Dict): Discovered network interfaces and configurations
        tool_map (Dict): Map of tool IDs to tool instances

    Example:
        >>> manager = ReconManager("auth-token", "https://server.com")
        >>> scans = manager.get_scheduled_scans()
        >>> for scan in scans:
        ...     manager.scan_func(scan)

    Note:
        - Implements singleton pattern via get_recon_manager() factory
        - All server communication is encrypted using AES-EAX mode
        - Supports automatic session renewal on authentication failure
        - Thread-safe for concurrent scan operations
    """

    def __init__(self, token: str, manager_url: str) -> None:
        """
        Initialize ReconManager with authentication and tool discovery.

        This constructor performs the complete setup required for reconnaissance
        operations including authentication, network discovery, tool registration,
        and server communication establishment.

        Initialization process:
        1. Store authentication credentials and server URL
        2. Discover available network interfaces
        3. Load and register available scanning tools locally

        Server registration (RSA key exchange, tool ID mapping) is handled
        separately by register_with_server(), called from get_recon_manager().

        Args:
            token (str): Authentication token for server communication
            manager_url (str): Base URL of the management server

        Raises:
            SessionException: If session establishment or tool registration fails

        Example:
            >>> manager = ReconManager("my-auth-token", "https://mgmt.example.com")

        Note:
            - Session key is automatically generated and exchanged
            - Network interfaces are discovered using netifaces
            - Tools are dynamically loaded from data_model
            - Server must respond with valid tool mapping for success
        """
        # Store authentication and connection details
        self.token = token
        self.debug = False
        self.manager_url = manager_url
        self._api_client = None

        # Discover available network interfaces
        self.network_ifaces = self.get_network_interfaces()

        # Initialize tool management — this is pure local work, done once
        self.tool_map: Dict[str, Any] = {}
        tool_classes = data_model.get_tool_classes()

        # Create tool instances from available tool classes
        self._tool_name_inst_map: Dict[str, Any] = {}
        for tool_class in tool_classes:
            tool_inst = tool_class()
            self._tool_name_inst_map[tool_inst.name] = tool_inst

        # Serialize tool descriptors once — calls modules_func() per tool
        # (fingerprinting, version checks, module enumeration) which is
        # expensive.  Cached here so retries don't repeat the work.
        self._collector_tools: List[Dict[str, Any]] = [
            tool_obj.to_jsonable() for tool_obj in self._tool_name_inst_map.values()
        ]

    def register_with_server(self) -> None:
        """
        Register collector with the management server and map tool IDs.

        Creates (or re-creates) the API client, sends the collector's network
        interfaces and tool list to the server, receives back the server-assigned
        tool ID mapping, and populates tool_map.  Can be called again
        on reconnect without re-importing tool modules.

        Raises:
            SessionException: If the server doesn't return a valid tool mapping
        """
        # Create / re-create API client (performs RSA key exchange)
        try:
            self._api_client = ApiClient(self.token, self.manager_url)
        except Exception as e:
            raise SessionException('Failed to establish session with server: %s' % e) from e

        collector_data = {
            'interfaces': self.network_ifaces,
            'tools': self._collector_tools,
        }

        # Register collector with server and get tool mappings
        try:
            ret_obj = self._api_client.update_collector(collector_data)
        except Exception as e:
            raise SessionException('Failed to register collector with server: %s' % e) from e
        if ret_obj:
            if 'tool_name_id_map' in ret_obj:
                tool_name_id_map = ret_obj['tool_name_id_map']
                if len(tool_name_id_map) > 0:
                    # Map server tool IDs to local tool instances
                    self.tool_map = {}
                    for tool_name in tool_name_id_map:
                        tool_id = tool_name_id_map[tool_name]
                        tool_id_hex = format(int(tool_id), 'x')
                        if tool_name in self._tool_name_inst_map:
                            self.tool_map[tool_id_hex] = self._tool_name_inst_map[tool_name]
                        else:
                            logging.getLogger(__name__).debug(
                                '%s tool not found in tool name instance map.' % tool_name
                            )
                    return

        # If we reach here, registration failed
        raise SessionException('Failed to register collector with server')

    def get_tool_map(self) -> Dict[str, Any]:
        """
        Get the mapping of tool IDs to tool instances.

        Returns:
            Dict[str, Any]: Dictionary mapping hex tool IDs to tool instances

        Example:
            >>> tool_map = manager.get_tool_map()
            >>> nmap_tool = tool_map.get("a1b2c3")
        """
        return self.tool_map

    def scan_func(self, scan_input: data_model.ScheduledScan) -> bool:
        """
        Execute the scan function for the currently active tool.

        This method delegates scan execution to the appropriate tool instance
        based on the current tool configuration in the scan context.

        Args:
            scan_input (ScheduledScan): Scan context with current tool information

        Returns:
            bool: True if scan executed successfully, False otherwise

        Example:
            >>> success = manager.scan_func(scheduled_scan)
            >>> if not success:
            ...     print("Scan execution failed")

        Note:
            - Tool must be registered in tool_map
            - Current tool is set in scan_input.current_tool
            - Tool-specific scan_func() method is called
        """
        # Initialize return value
        ret_val = False
        tool_id = scan_input.current_tool.id

        if tool_id in self.tool_map:
            tool_inst = self.tool_map[tool_id]
            # Delegate to tool-specific scan function
            ret_val = tool_inst.scan_func(scan_input)
        else:
            logging.getLogger(__name__).warning('%s tool does not exist in table.' % tool_id)

        return ret_val

    def import_func(self, scan_input: data_model.ScheduledScan) -> bool:
        """
        Import scan results using the appropriate tool's import function.

        This method delegates result import to the appropriate tool instance
        based on the current tool configuration in the scan context.

        Args:
            scan_input (ScheduledScan): Scan context with current tool information

        Returns:
            bool: True if import completed successfully, False otherwise

        Example:
            >>> success = manager.import_func(scheduled_scan)
            >>> if not success:
            ...     print("Result import failed")

        Note:
            - Tool must be registered in tool_map
            - Current tool is set in scan_input.current_tool
            - Tool-specific import_func() method is called
        """
        ret_val = False
        tool_id = scan_input.current_tool.id

        if tool_id in self.tool_map:
            tool_inst = self.tool_map[tool_id]
            # Delegate to tool-specific import function
            ret_val = tool_inst.import_func(scan_input)
        else:
            logging.getLogger(__name__).debug(f'Error: {tool_id} tool does not exist in table.')

        return ret_val

    def get_network_interfaces(self) -> Dict[str, Dict[str, str]]:
        """
        Discover and return available network interfaces with their configurations.

        This method uses the netifaces library to discover all available network
        interfaces and their IP/MAC address configurations, excluding loopback
        interfaces.

        Returns:
            Dict[str, Dict[str, str]]: Dictionary mapping interface names to
                                     their configuration:
                {
                    'interface_name': {
                        'ipv4_addr': '192.168.1.100',
                        'netmask': '255.255.255.0',
                        'mac_address': '00:11:22:33:44:55'
                    }
                }

        Example:
            >>> interfaces = manager.get_network_interfaces()
            >>> for iface, config in interfaces.items():
            ...     print(f"{iface}: {config['ipv4_addr']}")

        Note:
            - Loopback interfaces (127.0.0.1) are excluded
            - Only interfaces with IPv4 addresses are included
            - MAC addresses are included when available
            - Used for server registration and scan configuration
        """
        interface_dict = {}
        ifaces = netifaces.interfaces()

        for if_name in ifaces:
            loop_back = False
            addrs = netifaces.ifaddresses(if_name)

            # Extract IPv4 address information
            if netifaces.AF_INET in addrs:
                ipv4_addr_arr = addrs[netifaces.AF_INET]
                for ipv4_obj in ipv4_addr_arr:
                    ip_str = ipv4_obj['addr']
                    netmask = ipv4_obj['netmask']

                    # Skip loopback interfaces
                    if ip_str == '127.0.0.1':
                        loop_back = True

                    # Use first IP address found
                    break
            else:
                # Skip interfaces without IPv4 addresses
                continue

            # Skip loopback interfaces
            if loop_back:
                continue

            # Extract MAC address if available
            mac_addr_str = ''
            if netifaces.AF_LINK in addrs:
                hardware_addr_arr = addrs[netifaces.AF_LINK]
                for hardware_addr_obj in hardware_addr_arr:
                    mac_addr_str = hardware_addr_obj['addr']
                    # Use first MAC address found
                    break

            # Store interface configuration
            interface_dict[if_name] = {
                'ipv4_addr': ip_str,
                'netmask': netmask,
                'mac_address': mac_addr_str,
            }

        return interface_dict

    def set_current_target(self, connection_manager: Optional[Any], target_id: str) -> None:
        """
        Configure the current target for scanning operations.

        This is a stub method that can be overridden by specific connection
        managers to perform target-specific configuration.

        Args:
            connection_manager (Optional[Any]): Connection manager instance
            target_id (str): Identifier of the target to configure

        Note:
            - Default implementation does nothing
            - Intended to be overridden for specific target management needs
            - Called before each scan to configure target context
        """
        return

    def is_load_balanced(self) -> bool:
        """
        Check if the reconnaissance manager is behind a load balancer.

        This is a stub method that can be overridden to detect load balancer
        configurations where some ports may always appear open.

        Returns:
            bool: False by default, can be overridden to return True

        Note:
            - Default implementation returns False
            - Can be overridden for load balancer detection
            - Used to adjust scanning behavior in load-balanced environments
        """
        return False

    def get_subnets(self, scan_id: str) -> List[str]:
        return self._api_client.get_subnets(scan_id)

    def get_wordlist(self, wordlist_id: str):
        return self._api_client.get_wordlist(wordlist_id)

    def get_scheduled_scans(self) -> List[Any]:
        return self._api_client.get_scheduled_scans()

    def collector_poll(self, log_str: Optional[str]) -> Optional[Dict[str, Any]]:
        return self._api_client.collector_poll(log_str)

    def get_scheduled_scan(self, sched_scan_id: str) -> Optional[Dict[str, Any]]:
        return self._api_client.get_scheduled_scan(sched_scan_id)

    def get_scan_status(self, scan_id: str) -> Optional[Any]:
        return self._api_client.get_scan_status(scan_id)

    def get_hosts(self, scan_id: str) -> List[Any]:
        return self._api_client.get_hosts(scan_id)

    def update_collector(self, collector_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return self._api_client.update_collector(collector_data)

    def update_scan_status(
        self, schedule_scan_id: str, status: int, err_msg: Optional[str] = None
    ) -> bool:
        return self._api_client.update_scan_status(schedule_scan_id, status, err_msg)

    def get_tool_status(self, tool_id: str) -> Optional[int]:
        return self._api_client.get_tool_status(tool_id)

    def update_tool_status(self, tool_id: str, status: int, status_message: str = '') -> bool:
        return self._api_client.update_tool_status(tool_id, status, status_message)

    def import_ports(self, port_arr: List[Any]) -> bool:
        return self._api_client.import_ports(port_arr)

    def import_ports_ext(self, scan_results_dict: Dict[str, Any]) -> bool:
        return self._api_client.import_ports_ext(scan_results_dict)

    def import_data(
        self, scan_id: str, tool_id: str, scan_results: List[Dict[str, Any]]
    ) -> List[Dict[str, str]]:
        return self._api_client.import_data(scan_id, tool_id, scan_results)

    def import_shodan_data(self, scan_id: str, shodan_arr: List[Any]) -> bool:
        return self._api_client.import_shodan_data(scan_id, shodan_arr)

    def import_screenshot(self, data_dict: Dict[str, Any]) -> bool:
        return self._api_client.import_screenshot(data_dict)

    def update_job_status(
        self,
        job_id: str,
        status: int,
        status_message: str = '',
        result: Optional[Dict[str, Any]] = None,
    ) -> bool:
        return self._api_client.update_job_status(job_id, status, status_message, result)

    def update_jobs_status_batch(self, entries: List[Dict[str, Any]]) -> bool:
        return self._api_client.update_jobs_status_batch(entries)

    def reset_api_pool(self) -> None:
        """Drop the manager connection pool after a launchpoint switch.

        Pooled keep-alive sockets are stale once the network route changes;
        the worker calls this after every launchpoint switch so the next
        manager POST opens a clean connection. Safe no-op if the client hasn't
        been created yet.
        """
        if self._api_client is not None:
            self._api_client.reset_pool()
