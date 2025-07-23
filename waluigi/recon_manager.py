"""
Waluigi Reconnaissance Manager Module

This module provides the core scanning orchestration and management functionality
for the Waluigi security scanning framework. It handles the complete lifecycle
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

import signal
import time
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from types import SimpleNamespace
from threading import Event, Thread
from waluigi import scan_cleanup, scan_utils
from waluigi import data_model
from functools import partial

import requests
import base64
import binascii
import json
import threading
import traceback
import os
import netifaces
import enum
import functools
import logging
import luigi
import zlib
from typing import Optional, Dict, List, Any, Union, Tuple


# Configuration Constants
custom_user_agent: str = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"

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
        >>> sorted_tools = sorted(tools, key=functools.cmp_to_key(tool_order_cmp))

    Note:
        - Tools with scan_order=None are given highest priority (executed first)
        - Used with functools.cmp_to_key() for Python 3 sorting compatibility
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


def encrypt_data(session_key: bytes, data: bytes) -> str:
    """
    Encrypt and compress data using AES-EAX mode for secure transmission.

    This function provides secure data encryption for communication with the
    management server. It combines compression and encryption to optimize
    both security and bandwidth usage.

    The encryption process:
    1. Compresses data using zlib for reduced payload size
    2. Encrypts compressed data using AES-EAX mode
    3. Combines nonce, authentication tag, and ciphertext
    4. Encodes the result as base64 for transport

    Args:
        session_key (bytes): AES session key for encryption (must be valid AES key size)
        data (bytes): Raw data to be encrypted and transmitted

    Returns:
        str: Base64-encoded encrypted data packet ready for transmission

    Example:
        >>> session_key = b'32-byte-aes-key-here-12345678901'
        >>> data = b'{"scan_results": "data"}'
        >>> encrypted = encrypt_data(session_key, data)
        >>> # Send encrypted data to server

    Note:
        - Uses AES-EAX mode for authenticated encryption
        - Compression reduces payload size for network efficiency
        - Output format: base64(nonce + tag + ciphertext)
        - Compatible with server-side decryption in ReconManager
    """
    # Compress data first to reduce payload size
    compressed_data = zlib.compress(data)

    # Create AES cipher in EAX mode for authenticated encryption
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(compressed_data)

    # Combine nonce, authentication tag, and ciphertext
    packet = cipher_aes.nonce + tag + ciphertext

    # Encode as base64 for safe transport
    b64_data = base64.b64encode(packet).decode()

    return b64_data


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
        failed_task_exception (Tuple): Static variable holding Luigi task failures
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

    # Static variable to hold luigi task failures for error reporting
    failed_task_exception: Optional[Tuple[Any, Exception]] = None

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

    @luigi.Task.event_handler(luigi.Event.FAILURE)
    def catch_failure(task: Any, exception: Exception) -> None:
        """
        Luigi event handler to capture task failures for error reporting.

        This static method captures Luigi task failures and stores them
        for inclusion in status updates to the management server.

        Args:
            task (Any): Luigi task that failed
            exception (Exception): Exception that caused the failure

        Note:
            - Called automatically by Luigi when tasks fail
            - Stored failures are included in tool status updates
            - Static method for Luigi event handler compatibility
        """
        ScheduledScanThread.failed_task_exception = (task, exception)

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
        self.recon_manager.set_current_target(
            self.connection_manager, target_id)

        # Sort tools by execution order for proper dependency handling
        collection_tools = scheduled_scan_obj.collection_tool_map.values()
        sorted_list = sorted(collection_tools,
                             key=functools.cmp_to_key(tool_order_cmp))

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
                    continue

                # Set initial status after continue checks
                ret_status = data_model.CollectionToolStatus.RUNNING.value

                # Apply argument overrides if specified
                if collection_tool_inst.args_override:
                    tool_obj.args = collection_tool_inst.args_override

                # Configure current tool for scan context
                scheduled_scan_obj.current_tool = tool_obj
                scheduled_scan_obj.current_tool_instance_id = collection_tool_inst.id

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
                    continue

                # Update tool status to running
                scheduled_scan_obj.update_tool_status(
                    collection_tool_inst.id, data_model.CollectionToolStatus.RUNNING.value)

                # Handle active scanning tools that require target connection
                if tool_obj.tool_type == 2:

                    if self.connection_manager and self.connection_manager.connect_to_target() == False:
                        err_msg = "Failed connecting to target"
                        logging.getLogger(__name__).error(err_msg)
                        return err_msg

                    try:
                        # Execute the actual scanning function
                        if self.recon_manager.scan_func(scheduled_scan_obj) == False:
                            err_msg = "Scan function failed"
                            logging.getLogger(__name__).debug(err_msg)
                            ret_status = data_model.CollectionToolStatus.ERROR.value
                            break

                    except Exception as e:
                        err_msg = "Error calling scan function: %s" % str(e)
                        logging.getLogger(__name__).error(err_msg)
                        logging.getLogger(__name__).debug(
                            traceback.format_exc())
                        ret_status = data_model.CollectionToolStatus.ERROR.value
                        break
                    finally:
                        # Handle Luigi task failures and update status
                        err_msg = ''
                        if ScheduledScanThread.failed_task_exception:
                            err_msg = f"{ScheduledScanThread.failed_task_exception[0]}\n{ScheduledScanThread.failed_task_exception[1]}"
                            ScheduledScanThread.failed_task_exception = None

                        if self.connection_manager and self.connection_manager.connect_to_extender() == False:
                            err_msg = "Failed connecting to extender"
                            logging.getLogger(__name__).error(err_msg)
                            return err_msg

                        # Update the tool status after connecting back to extender
                        scheduled_scan_obj.update_tool_status(
                            collection_tool_inst.id, ret_status, err_msg)

                # Import scan results regardless of tool type
                try:
                    if self.recon_manager.import_func(scheduled_scan_obj) == False:
                        err_msg = "Import function failed"
                        logging.getLogger(__name__).debug(err_msg)
                        ret_status = data_model.CollectionToolStatus.ERROR.value
                        break
                    else:
                        ret_status = data_model.CollectionToolStatus.COMPLETED.value
                except Exception as e:
                    err_msg = "Error calling import function: %s" % str(e)
                    logging.getLogger(__name__).error(err_msg)
                    logging.getLogger(__name__).debug(traceback.format_exc())
                    ret_status = data_model.CollectionToolStatus.ERROR.value
                    break

                finally:
                    # Final status update with Luigi failure handling
                    err_msg = None
                    if ScheduledScanThread.failed_task_exception:
                        err_msg = f"{ScheduledScanThread.failed_task_exception[0]}\n{ScheduledScanThread.failed_task_exception[1]}"
                        ScheduledScanThread.failed_task_exception = None

                    scheduled_scan_obj.update_tool_status(
                        collection_tool_inst.id, ret_status, err_msg)

            finally:
                # Clean up current tool references
                scheduled_scan_obj.current_tool = None
                scheduled_scan_obj.current_tool_instance_id = None

        # Perform scan cleanup on successful completion
        if ret_status == data_model.CollectionToolStatus.COMPLETED.value:
            scan_cleanup.scan_cleanup_func(scheduled_scan_obj.id)
            err_msg = None

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
        lock_val = None
        try:
            if self.connection_manager:
                for _ in range(20):
                    lock_val = self.connection_manager.get_connection_lock()
                    if lock_val is None:
                        logging.getLogger(__name__).debug(
                            "Connection lock is currently held. Retrying later")
                        time.sleep(1)
                    break

            err_msg = self.execute_scan_jobs(scheduled_scan_obj)

            # Ensure connection to extender for status updates
            if self.connection_manager and self.connection_manager.connect_to_extender() == False:
                logging.getLogger(__name__).error(
                    "Failed connecting to extender")
                return False

            if err_msg is None:
                # Scan completed successfully
                scan_status = data_model.ScanStatus.COMPLETED.value

                # Perform resource cleanup
                scheduled_scan_obj.cleanup()

        except Exception as e:
            logging.getLogger(__name__).error("Error executing scan job")
            logging.getLogger(__name__).debug(traceback.format_exc())
        finally:
            # Always release connection lock
            if self.connection_manager and lock_val is not None:
                self.connection_manager.free_connection_lock(lock_val)

        with self.scan_thread_lock:
            # Update final scan status on server
            scheduled_scan_obj.update_scan_status(scan_status)
            # Remove scan from active tracking
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
                while self._is_running:

                    # Wait for next polling cycle or exit signal
                    self.exit_event.wait(self.checkin_interval)
                    if self._enabled:
                        lock_val = None
                        try:
                            # Acquire connection lock if using connection manager
                            if self.connection_manager:
                                lock_val = self.connection_manager.get_connection_lock()
                                if lock_val:
                                    logging.getLogger(__name__).debug(
                                        "ScheduledScanThread connecting to extender")
                                    ret_val = self.connection_manager.connect_to_extender()
                                    if ret_val == False:
                                        logging.getLogger(__name__).error(
                                            "Failed connecting to extender")
                                        continue
                                else:
                                    logging.getLogger(__name__).debug(
                                        "Connection lock is currently held. Retrying later")
                                    continue

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

                            # Process scheduled scans with thread safety
                            with self.scan_thread_lock:
                                sched_scan_obj_arr = recon_manager.get_scheduled_scans()
                                for sched_scan_obj in sched_scan_obj_arr:

                                    # Handle new scans
                                    if sched_scan_obj.id not in self.scheduled_scan_map:

                                        # Create new scheduled scan instance
                                        scheduled_scan_obj = data_model.ScheduledScan(
                                            self, sched_scan_obj)
                                        self.scheduled_scan_map[sched_scan_obj.id] = scheduled_scan_obj

                                        # Start scan processing in separate thread
                                        Thread(target=partial(
                                            self.process_scan_obj, scheduled_scan_obj)).start()

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
                                        else:
                                            # Process individual tool cancellation
                                            cancelled_tool_ids = status_obj.cancelled_tool_ids

                                            # Terminate cancelled tools
                                            if len(cancelled_tool_ids) > 0:
                                                scheduled_scan_obj.kill_scan_processes(
                                                    cancelled_tool_ids)

                        except requests.exceptions.ConnectionError as e:
                            logging.getLogger(__name__).error(
                                "Unable to connect to server.")
                            pass
                        except Exception as e:
                            logging.getLogger(__name__).debug(
                                traceback.format_exc())
                            pass
                        finally:
                            # Always release connection lock
                            if self.connection_manager and lock_val is not None:
                                self.connection_manager.free_connection_lock(
                                    lock_val)

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
    if recon_mgr_inst == None:
        recon_mgr_inst = ReconManager(token, manager_url)
    return recon_mgr_inst


class ReconManager:
    """
    Central manager for reconnaissance operations and server communication.

    This class serves as the primary interface between the Waluigi scanning
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
        waluigi_tool_map (Dict): Map of tool IDs to tool instances

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
        2. Establish secure session with server (RSA key exchange)
        3. Discover available network interfaces
        4. Load and register available scanning tools
        5. Send collector configuration to server
        6. Map server tool IDs to local tool instances

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
        self.headers = {'User-Agent': custom_user_agent,
                        'Authorization': 'Bearer ' + self.token}

        # Establish secure session with server
        self.session_key = self._get_session_key()

        # Discover available network interfaces
        self.network_ifaces = self.get_network_interfaces()

        # Initialize tool management
        self.waluigi_tool_map: Dict[str, Any] = {}
        tool_classes = data_model.get_tool_classes()

        # Create tool instances from available tool classes
        tool_name_inst_map = {}
        for tool_class in tool_classes:
            tool_inst = tool_class()
            tool_name_inst_map[tool_inst.name] = tool_inst

        # Prepare collector data for server registration
        collector_tools = []
        for tool_obj in tool_name_inst_map.values():
            collector_tools.append(tool_obj.to_jsonable())

        collector_data = {
            'interfaces': self.network_ifaces,
            'tools': collector_tools
        }

        # Register collector with server and get tool mappings
        ret_obj = self.update_collector(collector_data)
        if ret_obj:
            if 'tool_name_id_map' in ret_obj:
                tool_name_id_map = ret_obj['tool_name_id_map']
                if len(tool_name_id_map) > 0:
                    # Map server tool IDs to local tool instances
                    for tool_name in tool_name_id_map:
                        tool_id = tool_name_id_map[tool_name]
                        tool_id_hex = format(int(tool_id), 'x')
                        if tool_name in tool_name_inst_map:
                            self.waluigi_tool_map[tool_id_hex] = tool_name_inst_map[tool_name]
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
        return self.waluigi_tool_map

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
            - Tool must be registered in waluigi_tool_map
            - Current tool is set in scan_input.current_tool
            - Tool-specific scan_func() method is called
        """
        # Initialize return value
        ret_val = False
        tool_id = scan_input.current_tool.id

        if tool_id in self.waluigi_tool_map:
            tool_inst = self.waluigi_tool_map[tool_id]
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
            - Tool must be registered in waluigi_tool_map
            - Current tool is set in scan_input.current_tool
            - Tool-specific import_func() method is called
        """
        ret_val = False
        tool_id = scan_input.current_tool.id

        if tool_id in self.waluigi_tool_map:
            tool_inst = self.waluigi_tool_map[tool_id]
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

    def _decrypt_json(self, content: Dict[str, str]) -> Optional[bytes]:
        """
        Decrypt JSON data received from the management server.

        This method handles the complete decryption process for server responses,
        including error recovery through session key refresh and automatic
        retry mechanisms.

        Decryption process:
        1. Extract base64-encoded encrypted data from response
        2. Decode and split into nonce, tag, and ciphertext components
        3. Decrypt using current session key with AES-EAX mode
        4. Decompress decrypted data using zlib
        5. Handle decryption failures with session key recovery

        Args:
            content (Dict[str, str]): Server response containing encrypted 'data' field

        Returns:
            Optional[bytes]: Decrypted and decompressed data, None if decryption fails

        Example:
            >>> response = {"data": "base64_encrypted_data"}
            >>> decrypted = manager._decrypt_json(response)
            >>> if decrypted:
            ...     result = json.loads(decrypted)

        Note:
            - Implements automatic session recovery on decryption failure
            - Removes corrupted session files and generates new session keys
            - Uses AES-EAX mode for authenticated encryption
            - Handles compression/decompression transparently
        """
        data = None
        if 'data' in content:
            # Decode base64 encrypted data
            b64_data = content['data']
            enc_data = base64.b64decode(b64_data)

            # Extract encryption components (16-byte nonce, 16-byte tag, ciphertext)
            nonce = enc_data[:16]
            tag = enc_data[16:32]
            ciphertext = enc_data[32:]

            # Attempt decryption with current session key
            cipher_aes = AES.new(self.session_key, AES.MODE_EAX, nonce)
            try:
                compressed_data = cipher_aes.decrypt_and_verify(
                    ciphertext, tag)
                data = zlib.decompress(compressed_data)
            except Exception as e:
                logging.getLogger(__name__).error(
                    "Error decrypting response: %s" % str(e))

                # Attempt recovery using session key from disk
                session_key = self._get_session_key_from_disk()
                if session_key and session_key != self.session_key:
                    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
                    try:
                        compressed_data = cipher_aes.decrypt_and_verify(
                            ciphertext, tag)
                        data = zlib.decompress(compressed_data)
                        # Update current session key on successful recovery
                        self.session_key = session_key
                        return data
                    except Exception as e:
                        logging.getLogger(__name__).error(
                            "Error decrypting response with session from disk. Refreshing session: %s" % str(e))

                # Clean up corrupted session and generate new key
                os.remove('session')
                # Generate new session key for future requests
                self.session_key = self._get_session_key()

        return data

    def _get_session_key_from_disk(self) -> Optional[bytes]:
        """
        Load session key from disk storage.

        This method retrieves a previously stored session key from the
        'session' file in the current directory. The session key is stored
        as hexadecimal text for persistence across application restarts.

        Returns:
            Optional[bytes]: Session key as bytes if file exists, None otherwise

        Example:
            >>> key = manager._get_session_key_from_disk()
            >>> if key:
            ...     print("Session key loaded from disk")

        Note:
            - Session key is stored in hexadecimal format
            - File location is './session' in current working directory
            - Returns None if file doesn't exist or cannot be read
        """
        session_key = None
        if os.path.exists('session'):
            with open("session", "r") as file_fd:
                hex_session = file_fd.read().strip()

            # Convert hexadecimal string back to bytes
            session_key = binascii.unhexlify(hex_session)

        return session_key

    def _get_session_key(self) -> bytes:
        """
        Generate or retrieve AES session key for secure server communication.

        This method implements the complete session establishment protocol:
        1. Check for existing session key on disk
        2. Generate temporary RSA key pair for key exchange
        3. Send public key to server for session establishment
        4. Receive encrypted session key from server
        5. Decrypt session key using private RSA key
        6. Store session key to disk for persistence

        Returns:
            bytes: AES session key for encrypted communication

        Raises:
            SessionException: If session establishment fails

        Example:
            >>> session_key = manager._get_session_key()
            >>> # Session key is now ready for encrypted communication

        Security Details:
            - Uses 2048-bit RSA keys for key exchange
            - AES session key is encrypted with RSA-OAEP
            - Session key is stored with 0o777 permissions
            - Automatic fallback to disk-stored key when available
        """
        # Check for existing session key on disk first
        session_key = self._get_session_key_from_disk()
        if session_key:
            return session_key

        # Generate temporary RSA key pair for secure key exchange
        key = RSA.generate(2048)
        private_key = key.export_key(format='DER')
        public_key = key.publickey().export_key(format='DER')

        session_key = None
        # Send public key to server for session establishment
        b64_val = base64.b64encode(public_key).decode()
        r = requests.post('%s/api/session' % self.manager_url,
                          headers=self.headers,
                          json={"data": b64_val},
                          verify=False)

        if r.status_code != 200:
            logging.getLogger(__name__).error("Error retrieving session key.")
            raise SessionException("Session key exchange failed")

        if r.content:
            ret_json = r.json()
            if "data" in ret_json:
                # Receive and decrypt session key from server
                b64_session_key = ret_json['data']
                enc_session_key = base64.b64decode(b64_session_key)

                # Decrypt the session key using private RSA key
                private_key_obj = RSA.import_key(private_key)
                cipher_rsa = PKCS1_OAEP.new(private_key_obj)
                session_key = cipher_rsa.decrypt(enc_session_key)

                # Store session key to disk for persistence
                with open(os.open('session', os.O_CREAT | os.O_WRONLY, 0o777), 'w') as fh:
                    fh.write(binascii.hexlify(session_key).decode())

        return session_key

    def get_subnets(self, scan_id):

        subnets = []
        r = requests.get('%s/api/subnets/scan/%s' % (self.manager_url,
                         scan_id), headers=self.headers, verify=False)
        if r.status_code == 404:
            return subnets
        if r.status_code != 200:
            logging.getLogger(__name__).error(
                "Unknown Error retriving subnets")
            return subnets

        if r.content:
            subnet_obj_arr = None
            try:
                content = r.json()
                data = self._decrypt_json(content)
                subnet_obj_arr = json.loads(
                    data, object_hook=lambda d: SimpleNamespace(**d))
            except Exception as e:
                logging.getLogger(__name__).error(
                    "Error retrieving subnets: %s" % str(e))
                logging.getLogger(__name__).debug(traceback.format_exc())
                return subnets

            if subnet_obj_arr:
                for subnet in subnet_obj_arr:
                    ip = subnet.subnet
                    subnet_inst = ip + "/" + str(subnet.mask)
                    subnets.append(subnet_inst)

        return subnets

    def get_wordlist(self, wordlist_id):

        wordlist = None
        r = requests.get('%s/api/wordlist/%s' % (self.manager_url,
                         wordlist_id), headers=self.headers, verify=False)
        if r.status_code == 404:
            return wordlist
        if r.status_code != 200:
            logging.getLogger(__name__).error(
                "Unknown Error retrieving wordlist")
            return wordlist

        if r.content:
            try:
                content = r.json()
                data = self._decrypt_json(content)
                wordlist = json.loads(data)
            except Exception as e:
                logging.getLogger(__name__).error(
                    "Error retrieving wordlist: %s" % str(e))
                logging.getLogger(__name__).debug(traceback.format_exc())
                return wordlist

        return wordlist

    def get_target(self, scan_id):

        target_obj = None
        r = requests.get('%s/api/target/scan/%s' % (self.manager_url,
                         scan_id), headers=self.headers, verify=False)
        if r.status_code == 404:
            return target_obj
        if r.status_code != 200:
            logging.getLogger(__name__).error(
                "Unknown Error retrieving targets")
            return target_obj

        if r.content:
            try:
                content = r.json()
                if content:
                    data = self._decrypt_json(content)
                    target_obj = json.loads(
                        data, object_hook=lambda d: SimpleNamespace(**d))
            except Exception as e:
                logging.getLogger(__name__).error(
                    "Error retrieving target: %s" % str(e))
                logging.getLogger(__name__).debug(traceback.format_exc())

        return target_obj

    def get_urls(self, scan_id):

        urls = []
        r = requests.get('%s/api/urls/scan/%s' % (self.manager_url,
                         scan_id), headers=self.headers, verify=False)
        if r.status_code == 404:
            return urls
        if r.status_code != 200:
            logging.getLogger(__name__).error("Unknown Error retrieving urls")
            return urls

        if r.content:
            url_obj_arr = None
            try:
                content = r.json()
                data = self._decrypt_json(content)
                url_obj_arr = json.loads(
                    data, object_hook=lambda d: SimpleNamespace(**d))
            except Exception as e:
                logging.getLogger(__name__).error(
                    "Error retrieving urls: %s" % str(e))
                logging.getLogger(__name__).debug(traceback.format_exc())
                return urls

            if url_obj_arr:
                for url_obj in url_obj_arr:
                    url = url_obj.url
                    urls.append(url)

        return urls

    def get_scheduled_scans(self):

        sched_scan_arr = []
        r = requests.get('%s/api/scheduler/' %
                         (self.manager_url), headers=self.headers, verify=False)
        if r.status_code == 404:
            return sched_scan_arr
        elif r.status_code != 200:
            logging.getLogger(__name__).error(
                "Unknown Error retrieving scheduled scans")
            return sched_scan_arr

        if r.content:
            try:
                content = r.json()
                data = self._decrypt_json(content)
                if data:
                    sched_scan_arr = json.loads(
                        data, object_hook=lambda d: SimpleNamespace(**d))
            except Exception as e:
                logging.getLogger(__name__).error(
                    "Error retrieving scheduled scans: %s" % str(e))
                logging.getLogger(__name__).debug(traceback.format_exc())

        return sched_scan_arr

    def collector_poll(self, log_str):

        settings = None
        status_dict = {'logs': log_str}
        json_data = json.dumps(status_dict).encode()
        b64_val = encrypt_data(self.session_key, json_data)

        r = requests.post('%s/api/collector/poll' %
                          (self.manager_url), headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code == 404:
            return settings
        elif r.status_code != 200:
            logging.getLogger(__name__).error(
                "Unknown Error retrieving collector settings")
            return settings

        if r.content:
            try:
                content = r.json()
                data = self._decrypt_json(content)
                if data:
                    settings = json.loads(data)
            except Exception as e:
                logging.getLogger(__name__).error(
                    "Error retrieving collector settings: %s" % str(e))
                logging.getLogger(__name__).debug(traceback.format_exc())

        return settings

    def get_scheduled_scan(self, sched_scan_id):

        sched_scan = None
        r = requests.get('%s/api/scheduler/%s/scan/' % (self.manager_url, sched_scan_id), headers=self.headers,
                         verify=False)
        if r.status_code == 404:
            return sched_scan
        elif r.status_code != 200:
            logging.getLogger(__name__).error("Unknown Error retrieving scan")
            return sched_scan

        if r.content:
            try:
                content = r.json()
                data = self._decrypt_json(content)
                sched_scan = json.loads(data)
            except Exception as e:
                logging.getLogger(__name__).error(
                    "Error retrieving scan: %s" % str(e))
                logging.getLogger(__name__).debug(traceback.format_exc())

        return sched_scan

    def get_scan_status(self, scan_id):

        scan_status = None
        r = requests.get('%s/api/scan/%s/status' % (self.manager_url,
                         scan_id), headers=self.headers, verify=False)
        if r.status_code == 404:
            return scan_status
        elif r.status_code != 200:
            logging.getLogger(__name__).error("Unknown Error retrieving scan")
            return scan_status

        if r.content:
            try:
                content = r.json()
                data = self._decrypt_json(content)
                scan_status = json.loads(
                    data, object_hook=lambda d: SimpleNamespace(**d))
            except Exception as e:
                logging.getLogger(__name__).error(
                    "Error retrieving scan status: %s" % str(e))
                logging.getLogger(__name__).debug(traceback.format_exc())

        return scan_status

    def get_hosts(self, scan_id):

        port_arr = []
        r = requests.get('%s/api/hosts/scan/%s' % (self.manager_url,
                         scan_id), headers=self.headers, verify=False)
        if r.status_code == 404:
            return port_arr
        elif r.status_code != 200:
            logging.getLogger(__name__).error("Unknown Error retrieving hosts")
            return port_arr

        if r.content:
            try:
                content = r.json()
                data = self._decrypt_json(content)
                port_arr = json.loads(
                    data, object_hook=lambda d: SimpleNamespace(**d))
            except Exception as e:
                logging.getLogger(__name__).error(
                    "Error retrieving hosts: %s" % str(e))
                logging.getLogger(__name__).debug(traceback.format_exc())

        return port_arr

    def get_tools(self):

        tool_obj_arr = []
        r = requests.get('%s/api/tools' % (self.manager_url),
                         headers=self.headers, verify=False)
        if r.status_code == 404:
            return tool_obj_arr
        elif r.status_code != 200:
            logging.getLogger(__name__).error("Unknown Error retrieving tools")
            return tool_obj_arr

        if r.content:
            try:
                content = r.json()
                data = self._decrypt_json(content)
                tool_obj_arr = json.loads(
                    data, object_hook=lambda d: SimpleNamespace(**d))
            except Exception as e:
                logging.getLogger(__name__).error(
                    "Error retrieving tools: %s" % str(e))
                logging.getLogger(__name__).debug(traceback.format_exc())

        return tool_obj_arr

    def update_collector(self, collector_data):

        # Import the data to the manager
        json_data = json.dumps(collector_data).encode()
        b64_val = encrypt_data(self.session_key, json_data)
        r = requests.post('%s/api/collector' % (self.manager_url),
                          headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error updating collector interfaces.")

        ret_obj = None
        if r.content:
            try:
                content = r.json()
                data = self._decrypt_json(content)
                ret_obj = json.loads(data)
            except Exception as e:
                logging.getLogger(__name__).error(
                    "Error retrieving collector data: %s" % str(e))
                logging.getLogger(__name__).debug(traceback.format_exc())

        return ret_obj

    def update_scan_status(self, schedule_scan_id, status, err_msg=None):

        # Import the data to the manager
        status_dict = {'status': status, 'error_message': err_msg}
        json_data = json.dumps(status_dict).encode()

        b64_val = encrypt_data(self.session_key, json_data)
        r = requests.post('%s/api/scheduler/%s/' % (self.manager_url, schedule_scan_id),
                          headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error updating scan status.")

        return True

    def get_tool_status(self, tool_id):

        status = None
        r = requests.get('%s/api/tool/status/%s' % (self.manager_url,
                         tool_id), headers=self.headers, verify=False)
        if r.status_code == 404:
            return status
        if r.status_code != 200:
            logging.getLogger(__name__).error(
                "Unknown Error retrieving tool status")
            return status

        if r.content:
            try:
                content = r.json()
                data = self._decrypt_json(content)
                if data:
                    tool_inst = json.loads(
                        data, object_hook=lambda d: SimpleNamespace(**d))
                    status = tool_inst.status
            except Exception as e:
                logging.getLogger(__name__).error(
                    "Error retrieving tool status: %s" % str(e))
                logging.getLogger(__name__).debug(traceback.format_exc())

        return status

    def update_tool_status(self, tool_id, status, status_message=''):

        # Import the data to the manager
        status_dict = {'status': status, 'status_message': status_message}
        json_data = json.dumps(status_dict).encode()

        b64_val = encrypt_data(self.session_key, json_data)
        r = requests.post('%s/api/tool/status/%s' % (self.manager_url, tool_id),
                          headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error updating tool status.")

        return True

    def import_ports(self, port_arr):

        # Import the data to the manager
        json_data = json.dumps(port_arr).encode()

        b64_val = encrypt_data(self.session_key, json_data)
        r = requests.post('%s/api/ports' % self.manager_url,
                          headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error importing ports to manager server.")

        return True

    def import_ports_ext(self, scan_results_dict):

        # Import the data to the manager
        json_data = json.dumps(scan_results_dict).encode()
        b64_val = encrypt_data(self.session_key, json_data)
        r = requests.post('%s/api/ports/ext' % self.manager_url,
                          headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error importing ports to manager server.")

        return True

    def import_data(self, scan_id, tool_id, scan_results):

        scan_results_dict = {'tool_id': tool_id,
                             'scan_id': scan_id, 'obj_list': scan_results}

        # Import the data to the manager
        json_data = json.dumps(scan_results_dict).encode()
        b64_val = encrypt_data(self.session_key, json_data)
        r = requests.post('%s/api/data/import' % self.manager_url,
                          headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error importing ports to manager server.")

        record_arr = []
        if r.content:
            try:
                content = r.json()
                data = self._decrypt_json(content)
                if data:
                    record_arr = json.loads(data)
            except Exception as e:
                logging.getLogger(__name__).error(
                    "Error retrieving import response: %s" % str(e))
                logging.getLogger(__name__).debug(traceback.format_exc())

        return record_arr

    def import_shodan_data(self, scan_id, shodan_arr):

        # Import the data to the manager
        json_data = json.dumps(shodan_arr).encode()
        b64_val = encrypt_data(self.session_key, json_data)
        r = requests.post('%s/api/integration/shodan/import/%s' % (self.manager_url,
                          str(scan_id)), headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error importing ports to manager server.")

        return True

    def import_screenshot(self, data_dict: Dict[str, Any]) -> bool:
        """
        Import screenshot data to the management server.

        This method uploads screenshot data captured during web application
        scanning to the management server for storage and analysis. The data
        is encrypted before transmission for security.

        Args:
            data_dict (Dict[str, Any]): Screenshot data dictionary containing:
                - image data (base64 encoded or binary)
                - URL or target information
                - timestamp and metadata
                - scan context information

        Returns:
            bool: True if import was successful

        Raises:
            RuntimeError: If server returns non-200 status code

        Example:
            >>> screenshot_data = {
            ...     'url': 'https://example.com',
            ...     'image': base64_encoded_image,
            ...     'timestamp': '2024-01-01T12:00:00Z'
            ... }
            >>> success = manager.import_screenshot(screenshot_data)

        Note:
            - Data is automatically encrypted using session key
            - Screenshot data is wrapped in array format for server API
            - Error message mentions "ports" but this is for screenshots
        """
        # Wrap screenshot data in array format expected by server
        obj_data = [data_dict]

        # Encrypt and encode screenshot data
        json_data = json.dumps(obj_data).encode()
        b64_val = encrypt_data(self.session_key, json_data)

        # Upload screenshot data to server
        r = requests.post('%s/api/screenshots' % self.manager_url,
                          headers=self.headers,
                          json={"data": b64_val},
                          verify=False)

        if r.status_code != 200:
            raise RuntimeError(
                "[-] Error importing screenshot to manager server.")

        return True
