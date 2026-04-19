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

from types import SimpleNamespace
from threading import Event, Thread
from reverge_collector import scan_cleanup
from reverge_collector import data_model
from reverge_collector.api_client import ApiClient
from functools import partial, cmp_to_key

import logging
import os
import netifaces
import requests
import threading
import traceback
from typing import Optional, Dict, List, Any, Union, Tuple


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

    def __init__(self, message: str = "Unable to get session token") -> None:
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

    def __init__(self, message: str = "Scan not found on server") -> None:
        """
        Initialize ScanNotFoundException with error message.

        Args:
            message (str): Error message describing the scan not found error.
                          Defaults to "Scan not found on server"

        Example:
            >>> raise ScanNotFoundException("Scan ID 123 not found")
        """
        super().__init__(message)


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

    def __init__(self, recon_manager: 'ReconManager', connection_manager: Optional[Any] = None) -> None:
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

    def _process_scan_obj_with_slot(self, scheduled_scan_obj: data_model.ScheduledScan) -> None:
        """Run scan processing in a dedicated thread."""
        self.process_scan_obj(scheduled_scan_obj)

    def _flush_pending_job_completions(self) -> None:
        """Retry POSTing results for jobs that completed locally but failed to report."""
        with self.scan_thread_lock:
            pending = dict(self.pending_job_completions)

        for job_id, payload in pending.items():
            try:
                self.recon_manager.update_job_status(
                    job_id,
                    payload["status"],
                    status_message=payload["err_msg"] or "",
                    result=payload["result"],
                )
                logging.getLogger(__name__).debug(
                    "Job %s pending result flushed successfully", job_id)
                with self.scan_thread_lock:
                    self.pending_job_completions.pop(job_id, None)
                    self.scheduled_scan_map.pop(job_id, None)
            except Exception:
                logging.getLogger(__name__).warning(
                    "Job %s result flush failed; will retry next poll", job_id)

    def _process_job_with_slot(self, job_item) -> None:
        """Execute a CollectorJob and post results back to the server."""
        from reverge_collector.job_executor import run_job
        err_msg = None
        result = None
        try:
            if self.connection_manager:
                self.connection_manager.get_connection_lock()

            # connect_to_extender before any server communication
            if self.connection_manager and self.connection_manager.connect_to_extender() == False:
                raise RuntimeError("Failed connecting to extender")

            # Configure connection target for this scan
            target_id = job_item.target_id
            target_slug = self.recon_manager.get_target_slug(target_id)

            # Update status to RUNNING
            self.recon_manager.update_job_status(
                job_item.id, data_model.ScanStatus.RUNNING.value)

            try:
                # connect_to_target before executing the job
                if self.connection_manager and self.connection_manager.connect_to_target(target_slug) == False:
                    raise RuntimeError(
                        "Failed connecting to target %s" % job_item.target_id)

                result = run_job(job_item.job_type, job_item.args)

            finally:
                # Always return to extender after target work, whether run_job
                # succeeded or raised.
                if self.connection_manager:
                    self.connection_manager.connect_to_extender()

            # Post result + COMPLETED status
            try:
                self.recon_manager.update_job_status(
                    job_item.id,
                    data_model.ScanStatus.COMPLETED.value,
                    result=result,
                )
                logging.getLogger(__name__).debug(
                    "Job %s completed (exit_code=%s)",
                    job_item.id,
                    result.get('exit_code'),
                )
            except Exception:
                # Server unreachable / 5xx — keep job in scheduled_scan_map so
                # the poll loop won't re-dispatch it, and store the result so
                # the next poll iteration can retry the POST without re-running.
                logging.getLogger(__name__).warning(
                    "Job %s status POST failed; will retry on next poll",
                    job_item.id,
                )
                with self.scan_thread_lock:
                    self.pending_job_completions[job_item.id] = {
                        "status": data_model.ScanStatus.COMPLETED.value,
                        "result": result,
                        "err_msg": None,
                    }
                # Return without popping the job — it stays in scheduled_scan_map.
                return

        except Exception as e:
            err_msg = str(e)
            logging.getLogger(__name__).error(
                "Job %s failed: %s", job_item.id, e)
            logging.getLogger(__name__).debug(traceback.format_exc())
            try:
                self.recon_manager.update_job_status(
                    job_item.id,
                    data_model.ScanStatus.ERROR.value,
                    status_message=err_msg[:2048],
                )
            except Exception:
                # Server unreachable — store the error result for retry.
                logging.getLogger(__name__).warning(
                    "Job %s error-status POST failed; will retry on next poll",
                    job_item.id,
                )
                with self.scan_thread_lock:
                    self.pending_job_completions[job_item.id] = {
                        "status": data_model.ScanStatus.ERROR.value,
                        "result": None,
                        "err_msg": err_msg,
                    }
                return
        finally:
            if self.connection_manager:
                self.connection_manager.free_connection_lock()
            with self.scan_thread_lock:
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
            logging.getLogger(__name__).debug("Scan poller disabled.")
        else:
            self._enabled = True
            logging.getLogger(__name__).debug("Scan poller enabled.")

    def execute_scan_jobs(self, scheduled_scan_obj: data_model.ScheduledScan) -> Optional[str]:
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
        # Configure connection target for this scan
        target_id = scheduled_scan_obj.target_id
        target_slug = self.recon_manager.get_target_slug(target_id)

        # Sort tools by execution order for proper dependency handling
        collection_tools = scheduled_scan_obj.collection_tool_map.values()
        sorted_list = sorted(collection_tools,
                             key=cmp_to_key(tool_order_cmp))

        # Establish connection to extender for scan status monitoring
        if self.connection_manager and self.connection_manager.connect_to_extender() == False:
            err_msg = "Failed connecting to extender"
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
                        "Skipping tool %s due to disabled status or missing scan order", tool_obj.name)
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
                scan_status = self.recon_manager.get_scan_status(
                    scheduled_scan_obj.scan_id)
                if scan_status is None or scan_status.scan_status == data_model.ScanStatus.CANCELLED.value:
                    err_msg = "Scan cancelled or doesn't exist"
                    logging.getLogger(__name__).debug(err_msg)
                    # Perform cleanup for cancelled scan
                    scan_cleanup.scan_cleanup_func(scheduled_scan_obj.id)
                    return err_msg

                # Check for individual tool cancellation
                cancelled_tool_ids = scan_status.cancelled_tool_ids
                if collection_tool_inst.id in cancelled_tool_ids:
                    logging.getLogger(__name__).debug(
                        """Tool %s cancelled before execution, skipping""" % tool_obj.name)
                    continue

                # Update tool status to running
                scheduled_scan_obj.update_tool_status(
                    collection_tool_inst.id, data_model.CollectionToolStatus.RUNNING.value)

                try:
                    # Connect to target only for active scanning tools
                    if tool_obj.tool_type == 2:
                        if self.connection_manager and self.connection_manager.connect_to_target(target_slug) == False:
                            err_msg = "Failed connecting to target"
                            logging.getLogger(__name__).error(err_msg)
                            return err_msg

                    # Execute the actual scanning function
                    try:
                        if self.recon_manager.scan_func(scheduled_scan_obj) == False:
                            err_msg = "Scan function failed"
                            logging.getLogger(__name__).debug(err_msg)
                            ret_status = data_model.CollectionToolStatus.ERROR.value

                    except Exception as e:
                        err_msg = "Error calling scan function: %s" % str(e)
                        logging.getLogger(__name__).error(err_msg)
                        logging.getLogger(__name__).debug(
                            traceback.format_exc())
                        ret_status = data_model.CollectionToolStatus.ERROR.value

                    # Check for task failures
                    if self.failed_task_exception:
                        task_err = f"{self.failed_task_exception[0]}\n{self.failed_task_exception[1]}"
                        self.failed_task_exception = None
                        err_msg = task_err if not err_msg else f"{err_msg}\n{task_err}"

                finally:
                    if self.connection_manager and self.connection_manager.connect_to_extender() == False:
                        err_msg = "Failed connecting to extender"
                        logging.getLogger(__name__).error(err_msg)
                        return err_msg

                # If scan failed, update status and stop tool loop
                if ret_status == data_model.CollectionToolStatus.ERROR.value:
                    scheduled_scan_obj.update_tool_status(
                        collection_tool_inst.id, ret_status, err_msg)
                    break

                # Import scan results regardless of tool type
                import_err_msg = None
                try:
                    if self.recon_manager.import_func(scheduled_scan_obj) == False:
                        import_err_msg = "Import function failed"
                        logging.getLogger(__name__).debug(import_err_msg)
                        ret_status = data_model.CollectionToolStatus.IMPORT_FAILED.value
                    else:
                        ret_status = data_model.CollectionToolStatus.COMPLETED.value
                except Exception as e:
                    import_err_msg = "Error calling import function: %s" % str(e)
                    logging.getLogger(__name__).error(import_err_msg)
                    logging.getLogger(__name__).debug(traceback.format_exc())
                    ret_status = data_model.CollectionToolStatus.IMPORT_FAILED.value

                # Check for task failures from import
                if self.failed_task_exception:
                    task_err = f"{self.failed_task_exception[0]}\n{self.failed_task_exception[1]}"
                    self.failed_task_exception = None
                    import_err_msg = task_err if not import_err_msg else f"{import_err_msg}\n{task_err}"
                    ret_status = data_model.CollectionToolStatus.IMPORT_FAILED.value

                # Update tool status once after import
                scheduled_scan_obj.update_tool_status(
                    collection_tool_inst.id, ret_status, import_err_msg if import_err_msg else '')

                if ret_status == data_model.CollectionToolStatus.IMPORT_FAILED.value:
                    # The scan phase completed but the server POST failed (e.g.
                    # server down / 500).  Flag the scan so the scheduler keeps
                    # it RUNNING for retry on the next polling iteration.
                    # Subsequent tools are intentionally skipped because they
                    # may depend on this tool's results being in scope.
                    scheduled_scan_obj.has_pending_imports = True
                    break

            except Exception:
                logging.getLogger(__name__).error("Error executing scan job")
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
                if self.checkin_interval != poll_interval and poll_interval > 0 and poll_interval < 3600:
                    # Update the polling interval
                    self.checkin_interval = poll_interval
                    logging.getLogger(__name__).debug(
                        f"Updated poll interval to {poll_interval} seconds")

        except Exception as e:
            logging.getLogger(__name__).error(
                "Error processing collector settings: %s" % str(e))
            logging.getLogger(__name__).debug(traceback.format_exc())

    def process_scan_obj(self, scheduled_scan_obj: data_model.ScheduledScan) -> None:
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

        # Default to error status for safety
        scan_status = data_model.ScanStatus.ERROR.value
        try:
            if self.connection_manager:
                self.connection_manager.get_connection_lock()

            err_msg = self.execute_scan_jobs(scheduled_scan_obj)

            # Ensure connection to extender for status updates
            if self.connection_manager and self.connection_manager.connect_to_extender() == False:
                logging.getLogger(__name__).error(
                    "Failed connecting to extender")
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
                    "Scan %s has pending imports; leaving RUNNING for retry "
                    "on next poll iteration",
                    scheduled_scan_obj.id,
                )

        except Exception as e:
            logging.getLogger(__name__).error("Error executing scan job")
            logging.getLogger(__name__).debug(traceback.format_exc())
            if 'outage' in str(e):
                scan_status = data_model.ScanStatus.CANCELLED.value
        finally:

            try:
                # Always release connection lock
                if self.connection_manager:
                    self.connection_manager.connect_to_extender()

                # Update final scan status on server
                scheduled_scan_obj.update_scan_status(scan_status)

            except ScanNotFoundException as e:
                # Scan was deleted from server, remove from local tracking
                logging.getLogger(__name__).warning(
                    f"Scan {scheduled_scan_obj.id} not found on server, removing from local map: {e}")
                with self.scan_thread_lock:
                    if scheduled_scan_obj.id in self.scheduled_scan_map:
                        del self.scheduled_scan_map[scheduled_scan_obj.id]
            except Exception as e:
                logging.getLogger(__name__).debug(traceback.format_exc())
            finally:
                if self.connection_manager:
                    self.connection_manager.free_connection_lock()

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
                    if self._enabled:
                        try:
                            # Acquire connection lock if using connection manager
                            if self.connection_manager:
                                self.connection_manager.get_connection_lock()

                            # Collect log messages for transmission
                            result_str = None
                            result_list = []
                            if self.log_queue:
                                while not self.log_queue.empty() and len(result_list) < 100:
                                    result_list.append(
                                        self.log_queue.get())
                            if len(result_list) > 0:
                                result_str = "\n".join(result_list)

                            # Poll server for collector settings updates
                            collector_settings = recon_manager.collector_poll(
                                result_str)
                            if collector_settings:
                                self.process_collector_settings(
                                    collector_settings)

                            # Retry any job completions whose earlier POST failed.
                            self._flush_pending_job_completions()

                            # Process scheduled scans and jobs with thread safety
                            with self.scan_thread_lock:
                                sched_scan_obj_arr = recon_manager.get_scheduled_scans()
                                for sched_scan_obj in sched_scan_obj_arr:

                                    item_type = getattr(
                                        sched_scan_obj, '_type', 'scan')

                                    # --- Collector Job dispatch ---
                                    if item_type == 'job':
                                        if sched_scan_obj.id not in self.scheduled_scan_map:
                                            self.scheduled_scan_map[sched_scan_obj.id] = sched_scan_obj
                                            Thread(
                                                target=partial(
                                                    self._process_job_with_slot,
                                                    sched_scan_obj,
                                                )
                                            ).start()
                                        continue

                                    # --- Scan dispatch (unchanged) ---
                                    # Handle new scans
                                    if sched_scan_obj.id not in self.scheduled_scan_map:

                                        logging.getLogger(__name__).debug(
                                            "Processing new scan: %s", sched_scan_obj.id)

                                        # Create new scheduled scan instance
                                        scheduled_scan_obj = data_model.ScheduledScan(
                                            self, sched_scan_obj)
                                        self.scheduled_scan_map[sched_scan_obj.id] = scheduled_scan_obj

                                        # Start scan processing in separate thread
                                        Thread(
                                            target=partial(
                                                self._process_scan_obj_with_slot,
                                                scheduled_scan_obj,
                                            )
                                        ).start()

                                    else:

                                        # Handle existing scans - check for cancellation
                                        scheduled_scan_obj = self.scheduled_scan_map[sched_scan_obj.id]
                                        status_obj = self.recon_manager.get_scan_status(
                                            scheduled_scan_obj.scan_id)

                                        # Process scan cancellation
                                        if status_obj is None or status_obj.scan_status == data_model.ScanStatus.CANCELLED.value:
                                            logging.getLogger(__name__).debug(
                                                "Scan cancelled")
                                            scheduled_scan_obj.kill_scan_processes()

                                            # Remove from the map
                                            del self.scheduled_scan_map[scheduled_scan_obj.id]

                                        else:
                                            # Process individual tool cancellation
                                            cancelled_tool_ids = status_obj.cancelled_tool_ids

                                            # Terminate cancelled tools
                                            if len(cancelled_tool_ids) > 0:
                                                logging.getLogger(__name__).debug(
                                                    "Killing cancelled tools")
                                                scheduled_scan_obj.kill_scan_processes(
                                                    cancelled_tool_ids)

                        except requests.exceptions.ConnectionError as e:
                            logging.getLogger(__name__).error(
                                "Unable to connect to server.")
                            if self.connection_manager:
                                self.connection_manager.connect_to_extender()
                        except Exception as e:
                            logging.getLogger(__name__).debug(
                                traceback.format_exc())
                        finally:
                            # Always release connection lock
                            if self.connection_manager:
                                self.connection_manager.free_connection_lock()

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
            tool_obj.to_jsonable()
            for tool_obj in self._tool_name_inst_map.values()
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
            raise SessionException(
                "Failed to establish session with server: %s" % e) from e

        collector_data = {
            'interfaces': self.network_ifaces,
            'tools': self._collector_tools,
        }

        # Register collector with server and get tool mappings
        try:
            ret_obj = self._api_client.update_collector(collector_data)
        except Exception as e:
            raise SessionException(
                "Failed to register collector with server: %s" % e) from e
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
                                "%s tool not found in tool name instance map." % tool_name)
                    return

        # If we reach here, registration failed
        raise SessionException("Failed to register collector with server")

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
            logging.getLogger(__name__).warning(
                "%s tool does not exist in table." % tool_id)

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
            logging.getLogger(__name__).debug(
                f"Error: {tool_id} tool does not exist in table.")

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
                    if ip_str == "127.0.0.1":
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
            mac_addr_str = ""
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
                'mac_address': mac_addr_str
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

    def update_scan_status(self, schedule_scan_id: str, status: int, err_msg: Optional[str] = None) -> bool:
        return self._api_client.update_scan_status(schedule_scan_id, status, err_msg)

    def get_tool_status(self, tool_id: str) -> Optional[int]:
        return self._api_client.get_tool_status(tool_id)

    def update_tool_status(self, tool_id: str, status: int, status_message: str = '') -> bool:
        return self._api_client.update_tool_status(tool_id, status, status_message)

    def import_ports(self, port_arr: List[Any]) -> bool:
        return self._api_client.import_ports(port_arr)

    def import_ports_ext(self, scan_results_dict: Dict[str, Any]) -> bool:
        return self._api_client.import_ports_ext(scan_results_dict)

    def import_data(self, scan_id: str, tool_id: str, scan_results: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        return self._api_client.import_data(scan_id, tool_id, scan_results)

    def import_shodan_data(self, scan_id: str, shodan_arr: List[Any]) -> bool:
        return self._api_client.import_shodan_data(scan_id, shodan_arr)

    def import_screenshot(self, data_dict: Dict[str, Any]) -> bool:
        return self._api_client.import_screenshot(data_dict)

    def update_job_status(self, job_id: str, status: int,
                          status_message: str = "",
                          result: Optional[Dict[str, Any]] = None) -> bool:
        return self._api_client.update_job_status(
            job_id, status, status_message, result)
