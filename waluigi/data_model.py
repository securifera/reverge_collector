"""
Waluigi Data Model Module

This module provides the core data structures and classes for the Waluigi security scanning framework.
It defines various record types (hosts, ports, domains, vulnerabilities, etc.) and manages scan data
throughout the collection and analysis process.

The module handles:
- Data model definitions for security scan results
- Object serialization/deserialization 
- Data relationships and mappings
- Tool integration and execution management
- Scan result processing and aggregation

"""

import base64
import binascii
import enum
import hashlib
import threading
import uuid
from typing import List, Dict, Set, Optional, Union, Any, Tuple
import netaddr
import luigi
import os
import json
import importlib
import logging
import traceback
import signal

from waluigi.scan_utils import get_ports, construct_url

# Configuration: Available security scanning tools
# Each tuple contains (module_name, class_name) for dynamic tool loading
waluigi_tools: List[Tuple[str, str]] = [
    ('waluigi.masscan', 'Masscan'),          # Port scanner
    ('waluigi.nmap_scan', 'Nmap'),           # Network mapper and port scanner
    ('waluigi.pyshot_scan', 'Pyshot'),       # Screenshot capture tool
    ('waluigi.nuclei_scan', 'Nuclei'),       # Vulnerability scanner
    ('waluigi.subfinder_scan', 'Subfinder'),  # Subdomain discovery
    ('waluigi.feroxbuster_scan', 'Feroxbuster'),  # Directory/file brute forcer
    ('waluigi.shodan_lookup', 'Shodan'),     # Shodan API integration
    ('waluigi.httpx_scan', 'Httpx'),         # HTTP toolkit
    # SecurityTrails API integration
    ('waluigi.sectrails_ip_lookup', 'Sectrails'),
    ('waluigi.module_scan', 'Module'),       # Custom module execution
    ('waluigi.badsecrets_scan', 'Badsecrets'),  # Secret detection
    ('waluigi.webcap_scan', 'Webcap'),        # Web capture and analysis
    ('waluigi.gau_scan', 'Gau'),        # Web endpoint crawling results
    ('waluigi.python_scan', 'Python'),        # Python script execution
    # ('waluigi.divvycloud_lookup', 'Divvycloud')  # Cloud security integration (disabled)
]

# Global configuration: Wordlist storage path
wordlist_path: str = "/tmp/reverge_wordlist"
if not os.path.exists(wordlist_path):
    os.mkdir(wordlist_path)


def get_tool_classes() -> List[Any]:
    """
    Dynamically load and return all available Waluigi security scanning tool classes.

    This function imports each tool module specified in the waluigi_tools configuration
    and retrieves the corresponding class objects for tool instantiation.

    Returns:
        List[Any]: A list of tool class objects that can be instantiated for scanning

    Raises:
        ImportError: If a specified module cannot be imported
        AttributeError: If a specified class cannot be found in the module

    Example:
        >>> tools = get_tool_classes()
        >>> for tool_class in tools:
        ...     tool_instance = tool_class()
    """
    tool_classes: List[Any] = []

    for module_name, class_name in waluigi_tools:
        module = importlib.import_module(module_name)
        tool_class = getattr(module, class_name)
        tool_classes.append(tool_class)
    return tool_classes


def update_host_port_obj_map(scan_data: 'ScanData', port_id: str, host_port_obj_map: Dict[str, Dict[str, Any]]) -> None:
    """
    Update the host-port object mapping with scope-filtered port information.

    This function processes a port object and adds it to the host-port mapping if it meets
    the scope criteria (LOCAL or SCOPE tags). It creates mappings for both IP:port and
    domain:port combinations.

    Args:
        scan_data (ScanData): The scan data container with all network objects
        port_id (str): Unique identifier of the port to process
        host_port_obj_map (Dict[str, Dict[str, Any]]): Mapping to update with host:port -> {host_obj, port_obj}

    Returns:
        None: Modifies host_port_obj_map in place

    Note:
        Only processes ports with LOCAL or SCOPE tags to filter out irrelevant remote data

    Example:
        >>> host_port_obj_map = {}
        >>> update_host_port_obj_map(scan_data, "port_123", host_port_obj_map)
        >>> print(host_port_obj_map["192.168.1.1:80"])
        {'host_obj': <Host object>, 'port_obj': <Port object>}
    """

    tag_list = [RecordTag.SCOPE.value, RecordTag.LOCAL.value]

    port_obj = scan_data.port_map[port_id]
    # Exclude ports that originated remotely that aren't part of the scope
    if len(port_obj.tags.intersection(set(tag_list))) == 0:
        return

    # logging.getLogger(__name__).debug("Processing port: %s" % port_obj.to_jsonable())
    host_id = port_obj.parent.id
    if host_id in scan_data.host_map:
        host_obj = scan_data.host_map[host_id]
        # Exclude ports that originated remotely that aren't part of the scope
        if len(host_obj.tags.intersection(set(tag_list))) == 0:
            return

        host_port_str = "%s:%s" % (host_obj.ipv4_addr, port_obj.port)

        host_port_entry = {'host_obj': host_obj, 'port_obj': port_obj}
        host_port_obj_map[host_port_str] = host_port_entry

        if host_id in scan_data.domain_host_id_map:
            domain_obj_list = scan_data.domain_host_id_map[host_id]
            for domain_obj in domain_obj_list:

                # Exclude domains that originated remotely that aren't part of the scope
                if len(domain_obj.tags.intersection(set(tag_list))) == 0:
                    continue

                domain_port_str = "%s:%s" % (
                    domain_obj.name, port_obj.port)

                host_port_entry = {
                    'host_obj': host_obj, 'port_obj': port_obj}
                host_port_obj_map[domain_port_str] = host_port_entry

    # else:
    #    logging.getLogger(__name__).debug("Host not found in map: %s" % host_id)


class ScanStatus(enum.Enum):
    """
    Enumeration of possible scan execution states.

    This enumeration defines the lifecycle states of security scans, providing
    standardized status tracking throughout the scanning process. It enables
    consistent monitoring and reporting of scan progress across the system.

    Values:
        CREATED (1): Scan has been created but not yet started
        RUNNING (2): Scan is currently executing
        COMPLETED (3): Scan has finished successfully
        CANCELLED (4): Scan was cancelled by user or system
        ERROR (5): Scan failed due to an error

    Example:
        >>> scan.status = ScanStatus.RUNNING
        >>> if scan.status == ScanStatus.COMPLETED:
        ...     process_results(scan)

    Note:
        - Provides both integer values for database storage and string representations
        - Used for scan lifecycle management and user interface display
        - Supports conditional logic for scan state handling
    """
    CREATED = 1
    RUNNING = 2
    COMPLETED = 3
    CANCELLED = 4
    ERROR = 5

    def __str__(self) -> str:
        """
        Return string representation of scan status.

        Returns:
            str: Human-readable status name

        Example:
            >>> status = ScanStatus.RUNNING
            >>> print(f"Scan is {status}")  # "Scan is RUNNING"
        """
        if (self == ScanStatus.CREATED):
            return "CREATED"
        elif (self == ScanStatus.RUNNING):
            return "RUNNING"
        elif (self == ScanStatus.COMPLETED):
            return "COMPLETED"
        elif (self == ScanStatus.CANCELLED):
            return "CANCELLED"
        elif (self == ScanStatus.ERROR):
            return "ERROR"


class CollectionToolStatus(enum.Enum):
    """
    Enumeration of possible collection tool execution states.

    This enumeration tracks the individual execution status of scanning tools
    within a scan. Each tool in a scan can have its own status, allowing for
    granular monitoring and control of the scanning process.

    Values:
        CREATED (1): Tool instance created but not yet executed
        RUNNING (2): Tool is currently executing
        COMPLETED (3): Tool execution completed successfully
        ERROR (4): Tool execution failed with an error
        CANCELLED (5): Tool execution was cancelled

    Example:
        >>> tool.status = CollectionToolStatus.RUNNING
        >>> if tool.status == CollectionToolStatus.ERROR:
        ...     retry_tool(tool)

    Note:
        - Enables fine-grained control over individual tool execution
        - Supports partial scan recovery by tracking tool-level status
        - Used for progress reporting and error handling at tool level
    """
    CREATED = 1
    RUNNING = 2
    COMPLETED = 3
    ERROR = 4
    CANCELLED = 5

    def __str__(self) -> str:
        """
        Return string representation of collection tool status.

        Returns:
            str: Human-readable tool status name

        Example:
            >>> status = CollectionToolStatus.COMPLETED
            >>> print(f"Tool status: {status}")  # "Tool status: COMPLETED"
        """
        if (self == CollectionToolStatus.CREATED):
            return "CREATED"
        elif (self == CollectionToolStatus.RUNNING):
            return "RUNNING"
        elif (self == CollectionToolStatus.COMPLETED):
            return "COMPLETED"
        elif (self == CollectionToolStatus.ERROR):
            return "ERROR"
        elif (self == CollectionToolStatus.CANCELLED):
            return "CANCELLED"


class ScheduledScan():
    """
    Represents a scheduled security scan with its configuration and execution context.

    This class encapsulates all aspects of a scheduled scan including:
    - Tool configuration and wordlist management
    - Scan execution state and progress tracking
    - Resource management for concurrent tool execution
    - Network interface and target scope configuration
    - Process and thread lifecycle management

    The class handles the complete lifecycle of a scan from initialization through
    cleanup, managing wordlists, tool executors, and scan data throughout the process.

    Attributes:
        scan_thread (ScheduledScanThread): Parent thread managing this scan
        target_id (str): Identifier of the target being scanned
        scan_id (str): Unique identifier for this scan instance
        id (str): Scheduled scan identifier from the server
        tool_executor_map (Dict): Map of tool IDs to their executor instances
        tool_executor_lock (threading.Lock): Thread safety for executor operations
        collection_tool_map (Dict): Map of collection tools and their configurations
        current_tool (Optional): Currently executing tool instance
        current_tool_instance_id (Optional): ID of currently executing tool
        selected_interface (Optional): Network interface selected for scanning
        scan_data (data_model.ScanData): Scan scope and target information

    Example:
        >>> scan = ScheduledScan(scan_thread, scheduled_scan_config)
        >>> scan.update_scan_status(ScanStatus.RUNNING)
        >>> scan.register_tool_executor(tool_id, executor)

    Note:
        - Implements __hash__ method for Luigi task compatibility
        - Manages wordlist files and cleanup automatically
        - Supports concurrent tool execution with proper synchronization
    """

    def __init__(self, scheduled_scan_thread, scheduled_scan: Any) -> None:
        """
        Initialize a ScheduledScan instance with configuration and wordlist setup.

        This constructor handles the complete setup of a scan including:
        - Tool configuration and wordlist preparation
        - Network interface selection
        - Scan scope validation and setup
        - Initial status update to RUNNING

        Args:
            scheduled_scan_thread (ScheduledScanThread): Parent thread managing this scan
            scheduled_scan (Any): Server-provided scan configuration object

        Raises:
            RuntimeError: If scan object or scope is invalid/missing

        Example:
            >>> thread = ScheduledScanThread(recon_manager)
            >>> scan = ScheduledScan(thread, server_scan_config)
        """
        self.scan_thread = scheduled_scan_thread
        self.target_id = scheduled_scan.target_id
        self.scan_id = scheduled_scan.scan_id
        self.id = scheduled_scan.id
        self.tool_executor_map: Dict[str, Any] = {}
        self.tool_executor_lock = threading.Lock()

        # Initialize collection tool map with wordlist preparation
        self.collection_tool_map: Dict[str, Any] = {}
        for collection_tool in scheduled_scan.collection_tools:

            temp_wordlist_path = None
            # Only get wordlists for enabled tools
            if collection_tool.enabled == 1:
                # Prepare wordlist if present
                worlist_arr = []
                for wordlist in collection_tool.collection_tool.wordlists:
                    wordlist_id = wordlist.id
                    wordlist_hash = wordlist.hash
                    wordlist_json = None

                    # Check if wordlist file exists locally
                    file_path = os.path.join(
                        wordlist_path, str(wordlist_id))
                    if not os.path.exists(file_path):
                        # Download wordlist from server
                        wordlist_json = self.scan_thread.recon_manager.get_wordlist(
                            wordlist_id)
                        with open(file_path, 'w') as f:
                            json.dump(wordlist_json, f)

                    else:
                        try:
                            # Load existing wordlist and verify hash
                            with open(file_path, 'r') as f:
                                wordlist_json = json.load(f)

                            if 'hash' in wordlist_json:
                                if wordlist_json['hash'] != wordlist_hash:
                                    # Hash mismatch - re-download wordlist
                                    wordlist_json = self.scan_thread.recon_manager.get_wordlist(
                                        wordlist_id)
                                    with open(file_path, 'w') as f:
                                        json.dump(wordlist_json, f)
                            else:
                                raise Exception("No hash field")

                        except:
                            # Error loading wordlist - re-download
                            os.remove(file_path)
                            wordlist_json = self.scan_thread.recon_manager.get_wordlist(
                                wordlist_id)
                            with open(file_path, 'w') as f:
                                json.dump(wordlist_json, f)

                    # Add words to wordlist array
                    if wordlist_json and 'words' in wordlist_json:
                        worlist_arr.extend(wordlist_json['words'])

                # Create combined wordlist file for scan
                if len(worlist_arr) > 0:
                    temp_wordlist_path = os.path.join(
                        wordlist_path, str(collection_tool.id))
                    with open(temp_wordlist_path, 'w') as f:
                        f.write("\n".join(worlist_arr) + "\n")

            # Configure tool with wordlist path
            collection_tool.collection_tool.wordlist_path = temp_wordlist_path
            self.collection_tool_map[collection_tool.id] = collection_tool

        # Initialize execution state
        self.current_tool = None
        self.current_tool_instance_id = None
        self.selected_interface = None

        # Validate and retrieve scan configuration from server
        scan_obj = self.scan_thread.recon_manager.get_scheduled_scan(
            self.id)
        if scan_obj is None or 'scan_id' not in scan_obj or scan_obj['scan_id'] is None:
            raise RuntimeError(
                "[-] No scan object returned for scheduled scan.")
        else:
            self.scan_id = scan_obj['scan_id']

        # Validate scan scope
        if 'scope' not in scan_obj or scan_obj['scope'] is None:
            raise RuntimeError(
                "[-] No scan scope returned for scheduled scan.")

        # Initialize scan data with scope
        scope_dict = scan_obj['scope']
        self.scan_data = ScanData(
            scope_dict, record_tags=set([RecordTag.REMOTE.value]))

        # Configure selected network interface
        if 'interface' in scan_obj and scan_obj['interface']:
            self.selected_interface = scan_obj['interface']

        # Update scan status to running
        self.update_scan_status(ScanStatus.RUNNING.value)

    def update_scan_status(self, scan_status: int, err_msg: Optional[str] = None) -> None:
        """
        Update the overall scan status on the management server.

        Args:
            scan_status (int): New scan status value (from ScanStatus enum)
            err_msg (Optional[str]): Error message if status indicates failure

        Example:
            >>> scan.update_scan_status(ScanStatus.COMPLETED.value)
            >>> scan.update_scan_status(ScanStatus.ERROR.value, "Connection failed")
        """
        # Send update to the server
        self.scan_thread.recon_manager.update_scan_status(
            self.id, scan_status)

    def update_tool_status(self, tool_id: str, tool_status: int, tool_status_msg: str = '') -> None:
        """
        Update the status of a specific collection tool.

        Args:
            tool_id (str): Unique identifier of the tool to update
            tool_status (int): New tool status value (from CollectionToolStatus enum)
            tool_status_msg (str): Optional status message or error details

        Example:
            >>> scan.update_tool_status("nmap", CollectionToolStatus.RUNNING.value)
            >>> scan.update_tool_status("nuclei", CollectionToolStatus.ERROR.value, "Template load failed")
        """
        # Send update to the server
        self.scan_thread.recon_manager.update_tool_status(
            tool_id, tool_status, tool_status_msg)

        # Update in local collection tool map
        if tool_id in self.collection_tool_map:
            tool_obj = self.collection_tool_map[tool_id]
            tool_obj.status = tool_status

    def register_tool_executor(self, tool_id: str, tool_executor: Any) -> None:
        """
        Register tool executor for process and thread management.

        This method registers executors (processes and threads) associated with
        a tool so they can be properly cancelled or terminated if needed. It
        handles cleanup of completed futures to prevent memory leaks.

        Args:
            tool_id (str): Unique identifier of the tool
            tool_executor (Any): Executor instance with process PIDs and thread futures

        Example:
            >>> executor = ToolExecutor()
            >>> scan.register_tool_executor("nmap", executor)

        Note:
            This method has known memory leak issues and should be optimized
        """
        with self.tool_executor_lock:

            thread_future_array = tool_executor.get_thread_futures()
            proc_pids = tool_executor.get_process_pids()

            if tool_id in self.tool_executor_map:
                tool_executor_map_main = self.tool_executor_map[tool_id]
            else:
                tool_executor_map_main = ToolExecutor()
                self.tool_executor_map[tool_id] = tool_executor_map_main

            # Remove any completed futures to prevent memory leaks
            tool_executor_map_main.thread_future_array = [
                f for f in tool_executor_map_main.thread_future_array if not f.done()
            ]

            # Update the executor state
            if len(thread_future_array) > 0:
                tool_executor_map_main.thread_future_array.extend(
                    thread_future_array)
            tool_executor_map_main.proc_pids.update(proc_pids)

    def kill_scan_processes(self, tool_id_list: List[str] = []) -> None:
        """
        Terminate scan processes and cancel running threads.

        This method forcefully terminates all processes and cancels threads
        associated with specified tools or all tools if no list is provided.

        Args:
            tool_id_list (List[str]): List of tool IDs to terminate. 
                                    If empty, terminates all tools

        Example:
            >>> scan.kill_scan_processes(["nmap", "masscan"])  # Kill specific tools
            >>> scan.kill_scan_processes()  # Kill all tools

        Note:
            Uses SIGKILL for process termination - processes cannot ignore this signal
        """
        with self.tool_executor_lock:

            # Get the list of tool executors to process
            tool_executor_map_list = (
                [self.tool_executor_map[tool_id]
                    for tool_id in tool_id_list if tool_id in self.tool_executor_map]
                if tool_id_list else self.tool_executor_map.values()
            )

            # Terminate processes and cancel threads
            for executor in tool_executor_map_list:
                # Kill all processes with SIGKILL
                for pid in executor.get_process_pids():
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except:
                        pass
                # Cancel all thread futures
                for future in executor.get_thread_futures():
                    try:
                        future.cancel()
                    except:
                        pass

            # Cleanup tool_executor_map
            if tool_id_list:
                # Remove only specified tools
                self.tool_executor_map = {
                    k: v for k, v in self.tool_executor_map.items() if k not in tool_id_list}
            else:
                # Clear all tools
                self.tool_executor_map.clear()

    def cleanup(self) -> None:
        """
        Clean up temporary files and resources used during the scan.

        This method removes temporary wordlist files created for the scan
        and performs other cleanup operations to free system resources.

        Example:
            >>> scan.cleanup()  # Called after scan completion

        Note:
            Automatically called when scan completes successfully
        """
        collection_tools = self.collection_tool_map.values()
        for collection_tool_inst in collection_tools:
            # Remove the wordlist file if it exists
            if (collection_tool_inst.collection_tool.wordlist_path and
                    os.path.exists(collection_tool_inst.collection_tool.wordlist_path)):
                os.remove(collection_tool_inst.collection_tool.wordlist_path)

    def __hash__(self) -> int:
        """
        Return hash value for Luigi task compatibility.

        Luigi requires hashable input parameters for task deduplication.
        Since this object contains complex data structures that aren't
        naturally hashable, we return a constant value.

        Returns:
            int: Constant hash value (0) for Luigi compatibility

        Note:
            This is necessary because Luigi hashes input parameters and
            dictionaries won't work as task parameters
        """
        return 0


class CollectorType(enum.Enum):
    """
    Enumeration defining the types of security data collection methods.

    This enum categorizes scanning tools based on their interaction approach:
    - PASSIVE: Tools that collect data without actively probing targets
    - ACTIVE: Tools that actively probe and interact with targets

    Attributes:
        PASSIVE (int): Passive collection methods (value: 1)
        ACTIVE (int): Active scanning methods (value: 2)

    Example:
        >>> tool_type = CollectorType.PASSIVE
        >>> print(str(tool_type))
        'PASSIVE'
    """
    PASSIVE = 1  # Passive data collection (e.g., Shodan lookups, DNS queries)
    ACTIVE = 2   # Active scanning (e.g., port scanning, web crawling)

    def __str__(self) -> str:
        """
        Return string representation of the collector type.

        Returns:
            str: String representation ('PASSIVE', 'ACTIVE', or None)
        """
        if (self == CollectorType.PASSIVE):
            return "PASSIVE"
        elif (self == CollectorType.ACTIVE):
            return "ACTIVE"
        else:
            return None


class ToolExecutor:
    """
    Manages execution context for security scanning tools.

    This class tracks running threads and processes associated with tool execution,
    providing centralized management of concurrent scanning operations.

    Attributes:
        thread_future_array (List): List of concurrent.futures objects for thread tracking
        proc_pids (Set[int]): Set of process IDs for subprocess tracking

    Example:
        >>> executor = ToolExecutor()
        >>> futures = executor.get_thread_futures()
        >>> pids = executor.get_process_pids()
    """

    def __init__(self, thread_future_array: List[Any] = None, proc_pids: Set[int] = None) -> None:
        """
        Initialize the ToolExecutor with thread and process tracking collections.

        Args:
            thread_future_array (List[Any], optional): List of future objects for thread tracking
            proc_pids (Set[int], optional): Set of process IDs for subprocess tracking
        """
        self.thread_future_array: List[Any] = thread_future_array or []
        self.proc_pids: Set[int] = proc_pids or set()

    def get_thread_futures(self) -> List[Any]:
        """
        Get the list of thread future objects being tracked.

        Returns:
            List[Any]: List of concurrent.futures objects
        """
        return self.thread_future_array

    def get_process_pids(self) -> Set[int]:
        """
        Get the set of process IDs being tracked.

        Returns:
            Set[int]: Set of process IDs for running subprocesses
        """
        return self.proc_pids


class RecordTag(enum.Enum):
    """
    Enumeration for categorizing data records based on their origin and scope.

    This enum helps filter and organize scan results based on where the data
    originated and whether it's within the defined scanning scope.

    Attributes:
        LOCAL (int): Data collected directly by local scanning tools (value: 1)
        REMOTE (int): Data obtained from remote sources/APIs (value: 2)  
        SCOPE (int): Data that falls within the defined scanning scope (value: 3)

    Example:
        >>> tag = RecordTag.SCOPE
        >>> print(str(tag))
        'SCOPE'
    """
    LOCAL = 1   # Data collected by local tools/scans
    REMOTE = 2  # Data from remote sources (APIs, databases)
    SCOPE = 3   # Data within the defined scanning scope

    def __str__(self) -> str:
        """
        Return string representation of the record tag.

        Returns:
            str: String representation ('LOCAL', 'REMOTE', 'SCOPE', or None)
        """
        if (self == RecordTag.LOCAL):
            return "LOCAL"
        elif (self == RecordTag.REMOTE):
            return "REMOTE"
        elif (self == RecordTag.SCOPE):
            return "SCOPE"
        else:
            return None


class ServerRecordType(enum.Enum):
    """
    Enumeration of data record types for tool input/output validation.

    This enum defines the types of data records that tools can consume as inputs
    or produce as outputs, enabling validation of tool requirements against
    available scan data.

    Values:
        HOST: Host/IP address information
        PORT: Port and service information
        DOMAIN: Domain name information
        HTTP_ENDPOINT: HTTP endpoint information
        URL: URL information for web targets
        VULNERABILITY: Vulnerability and security finding data
        SCREENSHOT: Screenshot and visual data
        CERTIFICATE: SSL/TLS certificate information
        WEB_COMPONENT: Web technology stack information
        SUBNET: Network subnet information

    Example:
        >>> input_types = [ServerRecordType.HOST, ServerRecordType.PORT]
        >>> ServerRecordType.validate_type('HOST')
        True
    """
    HOST = "Host"
    PORT = "Port"
    DOMAIN = "Domain"
    HTTP_ENDPOINT = "HttpEndpoint"
    HTTP_ENDPOINT_DATA = "HttpEndpointData"
    VULNERABILITY = "Vuln"
    COLLECTION_MODULE = "CollectionModule"
    COLLECTION_MODULE_OUTPUT = "CollectionModuleOutput"
    SCREENSHOT = "Screenshot"
    CERTIFICATE = "Certificate"
    LIST_ITEM = "ListItem"
    WEB_COMPONENT = "WebComponent"
    SUBNET = "Subnet"

    def __str__(self) -> str:
        """Return string representation of the record type."""
        return self.value


class WaluigiTool:
    """
    Base class representing a security scanning tool within the Waluigi framework.

    This class encapsulates the configuration and metadata for individual security
    scanning tools, including their execution parameters, description, and callback functions.

    Attributes:
        name (str): Human-readable name of the tool
        collector_type (CollectorType): Type of collection method (ACTIVE/PASSIVE)
        scan_order (int): Execution order priority for the tool
        args (str): Command-line arguments or configuration parameters
        description (str): Detailed description of the tool's purpose and functionality
        project_url (str): URL to the tool's project page or documentation
        input_records (List[RecordType]): List of data types this tool can consume as input
        output_records (List[RecordType]): List of data types this tool produces as output
        scope_func (callable): Function to determine if tool should run on given scope
        scan_func (callable): Main scanning function that executes the tool
        import_func (callable): Function to import and process tool results

    Example:
        >>> tool = WaluigiTool()
        >>> tool.name = "Nmap"
        >>> tool.collector_type = CollectorType.ACTIVE
        >>> tool.input_records = [RecordType.HOST]
        >>> tool.output_records = [RecordType.PORT]
        >>> tool_data = tool.to_jsonable()
    """

    def __init__(self) -> None:
        """
        Initialize a new WaluigiTool instance with default values.

        All attributes are initialized to None and should be set by subclasses
        or during tool configuration.
        """
        self.name: Optional[str] = None
        self.collector_type: Optional[CollectorType] = None
        self.scan_order: Optional[int] = None
        self.args: Optional[str] = None
        self.description: Optional[str] = None
        self.project_url: Optional[str] = None
        self.input_records: List[ServerRecordType] = []
        self.output_records: List[ServerRecordType] = []
        self.scope_func: Optional[callable] = None
        self.scan_func: Optional[callable] = None
        self.import_func: Optional[callable] = None

    def to_jsonable(self) -> Dict[str, Any]:
        """
        Convert the tool configuration to a JSON-serializable dictionary.

        This method creates a dictionary representation of the tool's configuration
        that can be serialized to JSON for storage or transmission.

        Returns:
            Dict[str, Any]: Dictionary containing tool configuration data

        Example:
            >>> tool = WaluigiTool()
            >>> tool.name = "Nmap"
            >>> data = tool.to_jsonable()
            >>> print(data['name'])
            'Nmap'
        """
        ret_dict: Dict[str, Any] = {}
        ret_dict['name'] = self.name
        ret_dict['tool_type'] = self.collector_type
        ret_dict['scan_order'] = self.scan_order
        ret_dict['args'] = self.args
        ret_dict['description'] = self.description
        ret_dict['project_url'] = self.project_url
        ret_dict['input_records'] = [
            input_type.value for input_type in self.input_records]
        ret_dict['output_records'] = [
            output_type.value for output_type in self.output_records]
        return ret_dict


class ImportToolXOutput(luigi.Task):
    """
    Luigi Task for importing and processing security scanning tool output.

    This class handles the import of scan results from individual tools, processes them
    for database storage, and updates the scan scope with new findings. It manages the
    workflow of converting raw tool output into structured data objects.

    Attributes:
        scan_input: Reference to the scheduled scan object containing scan context

    Example:
        >>> import_task = ImportToolXOutput()
        >>> output_target = import_task.output()
        >>> is_complete = import_task.complete()
    """

    def output(self) -> luigi.LocalTarget:
        """
        Define the output target for the imported tool results.

        Creates a LocalTarget pointing to the processed import file that will contain
        the JSON-formatted scan results ready for database import.

        Returns:
            luigi.LocalTarget: Target file for the imported and processed results
        """
        tool_output_file = self.input().path
        dir_path = os.path.dirname(tool_output_file)
        out_file = dir_path + os.path.sep + "tool_import_json"

        return luigi.LocalTarget(out_file)

    def complete(self) -> bool:
        """
        Check if the import task is complete and update scan scope if needed.

        This method performs a custom completion check by verifying that the import
        file exists and contains valid JSON data. If complete, it updates the scan
        scope with the imported results.

        Returns:
            bool: True if the task is complete and scope has been updated, False otherwise

        Note:
            This method has the side effect of updating the scan scope when complete
        """
        # Custom completion check: Verify the scan objects exist and update the scope
        output = self.output()
        if output.exists():

            import_arr = []
            with open(output.path, 'r') as import_fd:
                for line in import_fd:
                    line = line.strip()
                    if not line:
                        continue
                    import_arr.append(json.loads(line))

            # Update the scope
            if len(import_arr) > 0:
                scheduled_scan_obj = self.scan_input
                scheduled_scan_obj.scan_data.update(import_arr)

                return True

        return False

    def import_results(self, scheduled_scan_obj: Any, obj_arr: List[Any]) -> None:
        """
        Import and process scan results from a security tool.

        This method takes raw scan objects, converts them to a database-compatible format,
        imports them to the server, updates IDs based on server response, and updates
        the local scan scope with the processed results.

        Args:
            scheduled_scan_obj: The scheduled scan object containing scan context and metadata
            obj_arr (List[Any]): List of scan result objects to import and process

        Returns:
            None: Results are written to file and scan scope is updated in place

        Raises:
            Exception: If there are issues with data serialization or server communication

        Example:
            >>> import_task = ImportToolXOutput()
            >>> results = [host_obj, port_obj, domain_obj]
            >>> import_task.import_results(scan_obj, results)
        """

        scan_id = scheduled_scan_obj.scan_id
        recon_manager = scheduled_scan_obj.scan_thread.recon_manager
        tool_id = scheduled_scan_obj.current_tool.id

        if len(obj_arr) > 0:

            record_map = {}
            import_arr = []
            for obj in obj_arr:
                # Add record to map
                record_map[obj.id] = obj
                flat_obj = obj.to_jsonable()
                import_arr.append(flat_obj)

            # logging.getLogger(__name__).debug("Imported:\n %s" % str(import_arr))

            # Import the results to the server
            updated_record_map = recon_manager.import_data(
                scan_id, tool_id, import_arr)

            # logging.getLogger(__name__).debug("Returned map: %d" % len(updated_record_map))

            updated_import_arr = update_scope_array(
                record_map, updated_record_map)

            # logging.getLogger(__name__).debug("Updated scope")

            # Write imported data to file
            tool_import_file = self.output().path
            with open(tool_import_file, 'w') as import_fd:
                import_fd.write(json.dumps(updated_import_arr))

            # logging.getLogger(__name__).debug("Updating server")

            # Update the scan scope
            scheduled_scan_obj.scan_data.update(updated_import_arr)
        else:
            logging.getLogger(__name__).warning(
                "No objects to import for scan %s" % scan_id)


def update_scope_array(record_map: Dict[str, Any], updated_record_map: Optional[List[Dict[str, str]]] = None) -> List[Dict[str, Any]]:
    """
    Update record IDs based on database responses and return updated scope array.

    This function processes records that have been imported to the database and updates
    their local IDs to match the database-assigned IDs. It also updates all references
    to these IDs in related objects to maintain data consistency.

    Args:
        record_map (Dict[str, Any]): Dictionary mapping record IDs to record objects
        updated_record_map (Optional[List[Dict[str, str]]]): List of ID mappings from database
            Each entry should contain 'orig_id' and 'db_id' keys

    Returns:
        List[Dict[str, Any]]: List of JSON-serializable record objects with updated IDs

    Note:
        This function modifies the record_map in place by updating IDs and references

    Example:
        >>> record_map = {'temp_123': host_obj}
        >>> db_updates = [{'orig_id': 'temp_123', 'db_id': 'host_456'}]
        >>> updated_records = update_scope_array(record_map, db_updates)
        >>> print(record_map['host_456'].id)  # 'host_456'
    """

    # Update the record map with those from the database
    if updated_record_map and len(updated_record_map) > 0:
        id_updates: Dict[str, str] = {}

        # Collect all updates
        for record_entry in updated_record_map:
            orig_id = record_entry['orig_id']
            db_id = record_entry['db_id']

            if orig_id in record_map and db_id != orig_id:
                record_obj = record_map[orig_id]
                record_obj.id = db_id

                id_updates[orig_id] = db_id
                record_map[db_id] = record_obj
                del record_map[orig_id]

        # Apply all updates in a single pass
        for record_obj in record_map.values():
            if record_obj.parent and record_obj.parent.id in id_updates:
                record_obj.parent.id = id_updates[record_obj.parent.id]

            if isinstance(record_obj, HttpEndpoint) and record_obj.web_path_id in id_updates:
                record_obj.web_path_id = id_updates[record_obj.web_path_id]

            if isinstance(record_obj, HttpEndpointData) and record_obj.domain_id in id_updates:
                record_obj.domain_id = id_updates[record_obj.domain_id]

    # Convert all records to JSON-serializable format
    import_arr: List[Dict[str, Any]] = []
    for obj_id in record_map:
        obj = record_map[obj_id]
        flat_obj = obj.to_jsonable()
        import_arr.append(flat_obj)

    return import_arr


class ScanData:
    """
    Central data container for managing security scan results and network topology.

    This class serves as the primary data structure for organizing and accessing all
    scan results, network objects, and their relationships. It provides methods for
    querying data by various criteria and maintains comprehensive mappings between
    different types of network objects.

    The class manages multiple types of security scan data:
    - Hosts and their IP addresses
    - Ports and services
    - Domains and DNS information  
    - HTTP endpoints and web data
    - Vulnerabilities and security findings
    - Screenshots and visual data
    - SSL/TLS certificates
    - Network components and modules

    Attributes:
        Various dictionaries and mappings for organizing scan data (see __init__)

    Example:
        >>> scan_data = ScanData(raw_data)
        >>> hosts = scan_data.get_hosts([RecordTag.SCOPE.value])
        >>> urls = scan_data.get_scope_urls()
    """

    def get_hosts(self, tag_list: Optional[List[str]] = None) -> List['Host']:
        """
        Retrieve host objects, optionally filtered by record tags.

        Args:
            tag_list (Optional[List[str]]): List of tag values to filter by (e.g., ['SCOPE', 'LOCAL'])
                                          If None, returns all hosts

        Returns:
            List[Host]: List of Host objects matching the filter criteria

        Example:
            >>> scope_hosts = scan_data.get_hosts([RecordTag.SCOPE.value])
            >>> all_hosts = scan_data.get_hosts()
        """
        host_list: List['Host'] = []
        host_map = self.host_map
        for host_id in host_map:
            host_obj = host_map[host_id]

            if tag_list:
                if host_obj.tags.intersection(set(tag_list)):
                    host_list.append(host_obj)
            else:
                host_list.append(host_obj)

        return host_list

    def get_domains(self, tag_list: Optional[List[str]] = None) -> List['Domain']:
        """
        Retrieve domain objects, optionally filtered by record tags.

        Args:
            tag_list (Optional[List[str]]): List of tag values to filter by
                                          If None, returns all domains

        Returns:
            List[Domain]: List of Domain objects matching the filter criteria

        Note:
            This method ensures domain names are unique in the returned list

        Example:
            >>> scope_domains = scan_data.get_domains([RecordTag.SCOPE.value])
        """
        domain_name_list: List['Domain'] = []
        seen_domain_names: Set[str] = set()
        domain_map = self.domain_map

        for domain_id in domain_map:
            domain_obj = domain_map[domain_id]

            # Check if domain name has already been seen
            if domain_obj.name in seen_domain_names:
                continue

            # Apply tag filtering if specified
            if tag_list:
                if domain_obj.tags.intersection(set(tag_list)):
                    domain_name_list.append(domain_obj)
                    seen_domain_names.add(domain_obj.name)
            else:
                domain_name_list.append(domain_obj)
                seen_domain_names.add(domain_obj.name)

        return domain_name_list

    def get_ports(self, tag_list: Optional[List[str]] = None) -> List['Port']:
        """
        Retrieve port objects, optionally filtered by record tags.

        Args:
            tag_list (Optional[List[str]]): List of tag values to filter by
                                          If None, returns all ports

        Returns:
            List[Port]: List of Port objects matching the filter criteria

        Example:
            >>> open_ports = scan_data.get_ports([RecordTag.SCOPE.value])
        """
        port_list: List['Port'] = []
        port_map = self.port_map
        for port_id in port_map:
            port_obj = port_map[port_id]
            if tag_list:
                if port_obj.tags.intersection(set(tag_list)):
                    port_list.append(port_obj)
            else:
                port_list.append(port_obj)

        return port_list

    def get_scope_urls(self) -> List[str]:
        """
        Extract all URLs from HTTP endpoints that are marked as within scope.

        This method searches through all HTTP endpoint data objects and returns
        the URLs for those marked with the SCOPE tag, providing a list of
        web targets for further analysis.

        Returns:
            List[str]: List of unique URLs within the scanning scope

        Example:
            >>> urls = scan_data.get_scope_urls()
            >>> print(urls)
            ['https://example.com:443/', 'http://test.com:80/admin']
        """
        endpoint_urls: Set[str] = set()
        http_endpoint_data_map = self.http_endpoint_data_map
        for http_endpoint_data_id in http_endpoint_data_map:
            http_endpoint_data_obj = http_endpoint_data_map[http_endpoint_data_id]
            if RecordTag.SCOPE.value in http_endpoint_data_obj.tags:
                url_str = http_endpoint_data_obj.get_url()
                if url_str:
                    endpoint_urls.add(url_str)

        return list(endpoint_urls)

    def get_urls(self) -> Dict[str, Dict[str, Any]]:
        """
        Extract all URLs suitable for screenshot capture with associated metadata.

        Returns:
            Dict[str, Dict[str, Any]]: Mapping of URLs to their metadata
            {
                "https://example.com:443/admin": {
                    "host_id": 123,
                    "port_id": 456,
                    "domain_id": 789,
                    "http_endpoint_id": 101,
                    "http_endpoint_data_id": 202,
                    "path": "/admin",
                    "domain": "example.com",
                    "secure": True
                }
            }
        """
        url_map = {}

        for target_key in self.host_port_obj_map:
            target_obj_dict = self.host_port_obj_map[target_key]
            port_obj = target_obj_dict['port_obj']
            host_obj = target_obj_dict['host_obj']

            port_id = port_obj.id
            port_str = port_obj.port
            secure = port_obj.secure
            host_id = host_obj.id
            ip_addr = host_obj.ipv4_addr
            domain_set = set()

            # Get all domains associated with the host
            if host_id and host_id in self.domain_host_id_map:
                temp_domain_list = self.domain_host_id_map[host_id]
                domain_set.update(
                    domain_obj.name for domain_obj in temp_domain_list)

            # Get all domains associated with the port
            if port_id and port_id in self.certificate_port_id_map:
                temp_cert_list = self.certificate_port_id_map[port_id]
                for cert_obj in temp_cert_list:
                    domain_set.update(cert_obj.domain_name_id_map.keys())

            # Extract domain from target if different from IP
            target_arr = target_key.split(":")
            if target_arr[0] != ip_addr:
                domain_set.add(target_arr[0])

            # Process HTTP endpoints
            if port_id in self.http_endpoint_port_id_map:
                self._process_http_endpoints(url_map, port_id, host_id, ip_addr,
                                             port_str, secure, domain_set)
            else:
                # Process likely HTTP ports without explicit endpoints
                self._process_likely_http_ports(url_map, port_id, host_id, ip_addr,
                                                port_str, secure, domain_set)

        return url_map

    def _process_http_endpoints(self, url_map, port_id, host_id, ip_addr,
                                port_str, secure, domain_set):
        """Process ports with known HTTP endpoints"""
        http_endpoint_obj_list = self.http_endpoint_port_id_map[port_id]

        for http_endpoint_obj in http_endpoint_obj_list:
            path = "/"
            web_path_id = http_endpoint_obj.web_path_id
            if web_path_id and web_path_id in self.path_map:
                web_path_obj = self.path_map[web_path_id]
                path = web_path_obj.web_path

            base_metadata = {
                "host_id": host_id,
                "port_id": port_id,
                "http_endpoint_id": http_endpoint_obj.id,
                "path": path,
                "secure": secure
            }

            if http_endpoint_obj.id in self.endpoint_data_endpoint_id_map:
                # Process endpoint data objects
                endpoint_data_list = self.endpoint_data_endpoint_id_map[http_endpoint_obj.id]
                for endpoint_data_obj in endpoint_data_list:
                    self._add_endpoint_data_urls(url_map, base_metadata, endpoint_data_obj,
                                                 ip_addr, port_str, secure, path)

            # Add base URL without endpoint data
            self._add_base_url(url_map, base_metadata, ip_addr, port_str,
                               secure, path, domain_set)

    def _process_likely_http_ports(self, url_map, port_id, host_id, ip_addr,
                                   port_str, secure, domain_set):
        """Process ports that are likely HTTP but don't have explicit endpoints"""
        likely_http = self._is_likely_http_port(port_id, port_str)

        if likely_http:
            base_metadata = {
                "host_id": host_id,
                "port_id": port_id,
                "path": "/",
                "secure": secure
            }
            self._add_base_url(url_map, base_metadata, ip_addr, port_str,
                               secure, "/", domain_set)

            # Add domain variants
            if host_id in self.domain_host_id_map:
                for domain_obj in self.domain_host_id_map[host_id]:
                    domain_metadata = base_metadata.copy()
                    domain_metadata["domain"] = domain_obj.name
                    domain_metadata["domain_id"] = domain_obj.id

                    url = construct_url(domain_obj.name, port_str, secure, "/")
                    if url:
                        url_map[url] = domain_metadata

    def _add_endpoint_data_urls(self, url_map, base_metadata, endpoint_data_obj,
                                ip_addr, port_str, secure, path):
        """Add URLs for endpoint data objects"""
        metadata = base_metadata.copy()
        metadata["http_endpoint_data_id"] = endpoint_data_obj.id

        host = ip_addr
        domain_id = endpoint_data_obj.domain_id
        if domain_id and domain_id in self.domain_map:
            domain_obj = self.domain_map[domain_id]
            metadata["domain"] = domain_obj.name
            metadata["domain_id"] = domain_id
            host = domain_obj.name

        # Add primary URL
        url = construct_url(host, port_str, secure, path)
        if url:
            url_map[url] = metadata

    def _add_base_url(self, url_map, base_metadata, ip_addr, port_str, secure, path, domain_set):
        """Add base URL without endpoint data"""
        for domain_str in domain_set:
            metadata = base_metadata.copy()
            metadata["domain"] = domain_str

            url = construct_url(domain_str, port_str, secure, path)
            if url:
                url_map[url] = metadata

        # Add IP version
        metadata = base_metadata.copy()
        url = construct_url(ip_addr, port_str, secure, path)
        if url:
            url_map[url] = metadata

    def _is_likely_http_port(self, port_id, port_str):
        """Determine if a port is likely HTTP"""
        if port_str in ['80', '443']:
            return True

        if port_id in self.component_port_id_map:
            for component_obj in self.component_port_id_map[port_id]:
                if 'http' in component_obj.name.lower():
                    return True

        return False

    def update(self, record_map: Union[Dict[str, Any], List[Any]]) -> None:
        """
        Update the scan data with new records from scan results.

        This method processes new scan data and integrates it into the existing
        data structure. It handles both dictionary and list formats of input data
        and automatically tags records as LOCAL.

        Args:
            record_map (Union[Dict[str, Any], List[Any]]): New scan data to integrate
                Can be either a dictionary of records or a list of record objects

        Returns:
            None: Updates the internal data structures in place

        Example:
            >>> new_data = [host_obj, port_obj, domain_obj]
            >>> scan_data.update(new_data)
        """
        # Parse the data
        import_list: List[Any] = []
        if isinstance(record_map, dict):
            import_list = list(record_map.values())
        else:
            import_list = record_map

        record_tags: Set[str] = set([RecordTag.LOCAL.value])
        self._process_data(import_list, record_tags)

        self._post_process()

    def _post_process(self) -> None:
        """
        Perform post-processing operations on scan data.

        This internal method is called after data processing to update
        derived data structures like host-port mappings.

        Returns:
            None: Updates internal mappings in place
        """
        for port_id in self.port_map:
            update_host_port_obj_map(self, port_id, self.host_port_obj_map)

    def _process_data(self, obj_list: List[Any], record_tags: Set[str] = None) -> None:
        """
        Process a list of scan objects and organize them into appropriate data structures.

        This internal method takes raw scan objects, converts them to Record objects
        if necessary, and sorts them into the appropriate mapping structures based
        on their type (Host, Port, Domain, etc.).

        Args:
            obj_list (List[Any]): List of scan objects to process
            record_tags (Set[str], optional): Set of tags to apply to processed records

        Returns:
            None: Updates internal data structures in place

        Note:
            This method handles all supported record types and maintains relationships
            between different types of network objects
        """
        record_tags = record_tags or set()

        for obj in obj_list:
            if not isinstance(obj, Record):
                record_obj = Record.static_from_jsonsable(
                    input_dict=obj, scan_data=self, record_tags=record_tags)
                if record_obj is None:
                    continue
            else:
                record_obj = obj

            # logging.getLogger(__name__).warning(
            #    "Processing record of type %s" % type(record_obj))
            if isinstance(record_obj, Host):

                # Get IP as unique index for map
                host_ip = record_obj.ipv4_addr
                self.host_ip_id_map[host_ip] = record_obj.id

                # Add to the host insert list
                self.host_map[record_obj.id] = record_obj

            elif isinstance(record_obj, Domain):

                # Get host ID of port obj
                host_id = record_obj.parent.id
                if host_id in self.domain_host_id_map:
                    temp_domain_list = self.domain_host_id_map[host_id]
                else:
                    temp_domain_list = []
                    self.domain_host_id_map[host_id] = temp_domain_list

                # Add domain obj to list to be updated
                temp_domain_list.append(record_obj)

                # Create domain name id mapping
                domain_name = record_obj.name
                self.domain_name_map[domain_name] = record_obj

                # Add domain obj to list for being imported
                self.domain_map[record_obj.id] = record_obj

            elif isinstance(record_obj, Port):

                # Create host id to port list map
                host_id = record_obj.parent.id
                if host_id in self.host_id_port_map:
                    temp_port_list = self.host_id_port_map[host_id]
                else:
                    temp_port_list = []
                    self.host_id_port_map[host_id] = temp_port_list

                 # Add port obj to list to be updated
                temp_port_list.append(record_obj)

                # Create port number to host id map
                host_id = record_obj.parent.id
                port_str = record_obj.port
                if port_str in self.port_host_map:
                    temp_host_id_set = self.port_host_map[port_str]
                else:
                    temp_host_id_set = set()
                    self.port_host_map[port_str] = temp_host_id_set

                # Add port obj to list to be updated
                temp_host_id_set.add(host_id)

                # Add port obj to list for being imported
                self.port_map[record_obj.id] = record_obj

            elif isinstance(record_obj, ListItem):

                # Get path hash
                if record_obj.web_path_hash:
                    screenshot_path_hash = record_obj.web_path_hash.upper()
                    if screenshot_path_hash in self.path_hash_id_map:
                        temp_screenshot_list = self.path_hash_id_map[screenshot_path_hash]
                    else:
                        temp_screenshot_list = []
                        self.path_hash_id_map[screenshot_path_hash] = temp_screenshot_list

                    # Add port obj to list to be updated
                    temp_screenshot_list.append(record_obj.id)

                # Add path obj to list for being imported
                self.path_map[record_obj.id] = record_obj

            elif isinstance(record_obj, WebComponent):

                # Get port id
                port_id = record_obj.parent.id
                if port_id in self.component_port_id_map:
                    temp_list = self.component_port_id_map[port_id]
                else:
                    temp_list = []
                    self.component_port_id_map[port_id] = temp_list
                # Add port obj to list to be updated
                temp_list.append(record_obj)

                # Create a mapping of component name to port id
                component_key = record_obj.name
                if record_obj.version:
                    component_key += ":" + record_obj.version

                if component_key in self.component_name_port_id_map:
                    temp_list = self.component_name_port_id_map[component_key]
                else:
                    temp_list = []
                    self.component_name_port_id_map[component_key] = temp_list

                # Add port obj to list to be updated
                temp_list.append(port_id)

                # Add component obj to list for being imported
                self.component_map[record_obj.id] = record_obj

            elif isinstance(record_obj, Screenshot):

                # Get screenshot hash
                if record_obj.image_hash:
                    screenshot_path_hash = record_obj.image_hash.upper()
                    if screenshot_path_hash in self.screenshot_hash_id_map:
                        temp_screenshot_list = self.screenshot_hash_id_map[screenshot_path_hash]
                    else:
                        temp_screenshot_list = []
                        self.screenshot_hash_id_map[screenshot_path_hash] = temp_screenshot_list

                    # Add screenshot obj to list to be updated
                    temp_screenshot_list.append(record_obj.id)

                # Add screenshot obj to list for being imported
                self.screenshot_map[record_obj.id] = record_obj

            elif isinstance(record_obj, HttpEndpoint):

                # Get path id
                web_path_id = record_obj.web_path_id
                if web_path_id in self.http_endpoint_path_id_map:
                    temp_endpoint_list = self.http_endpoint_path_id_map[web_path_id]
                else:
                    temp_endpoint_list = []
                    self.http_endpoint_path_id_map[web_path_id] = temp_endpoint_list

                # Add path obj to list to be updated
                temp_endpoint_list.append(record_obj)

                # Get port id
                port_id = record_obj.parent.id
                if port_id in self.http_endpoint_port_id_map:
                    temp_endpoint_list = self.http_endpoint_port_id_map[port_id]
                else:
                    temp_endpoint_list = []
                    self.http_endpoint_port_id_map[port_id] = temp_endpoint_list

                # Add port obj to list to be updated
                temp_endpoint_list.append(record_obj)

                # Add http endpoint obj to list for being imported
                self.http_endpoint_map[record_obj.id] = record_obj

            elif isinstance(record_obj, HttpEndpointData):

                # Get http endpoint
                http_endpoint_id = record_obj.parent.id
                if http_endpoint_id in self.endpoint_data_endpoint_id_map:
                    temp_endpoint_list = self.endpoint_data_endpoint_id_map[http_endpoint_id]
                else:
                    temp_endpoint_list = []
                    self.endpoint_data_endpoint_id_map[http_endpoint_id] = temp_endpoint_list

                # Add path obj to list to be updated
                temp_endpoint_list.append(record_obj)

                # Get screenshot id
                screenshot_id = record_obj.screenshot_id
                if screenshot_id in self.http_endpoint_data_screenshot_id_map:
                    temp_endpoint_list = self.http_endpoint_data_screenshot_id_map[screenshot_id]
                else:
                    temp_endpoint_list = []
                    self.http_endpoint_data_screenshot_id_map[screenshot_id] = temp_endpoint_list

                # Add screenshot obj to list to be updated
                temp_endpoint_list.append(record_obj)

                # Add http endpoint obj to list for being imported
                self.http_endpoint_data_map[record_obj.id] = record_obj

            elif isinstance(record_obj, Vuln):

                # Get vuln name
                vuln_name = record_obj.name
                if vuln_name in self.vulnerability_name_id_map:
                    temp_vuln_list = self.vulnerability_name_id_map[vuln_name]
                else:
                    temp_vuln_list = []
                    self.vulnerability_name_id_map[vuln_name] = temp_vuln_list

                # Add vuln obj to list
                temp_vuln_list.append(record_obj)

                # Add vulnerability obj to list for being imported
                self.vulnerability_map[record_obj.id] = record_obj

            elif isinstance(record_obj, CollectionModule):

                # Get module name
                module_name = record_obj.name
                if module_name in self.module_name_id_map:
                    temp_module_list = self.module_name_id_map[module_name]
                else:
                    temp_module_list = []
                    self.module_name_id_map[module_name] = temp_module_list

                # Add module obj to list
                temp_module_list.append(record_obj)

                # Add collection module obj to list for being imported
                self.collection_module_map[record_obj.id] = record_obj

            elif isinstance(record_obj, CollectionModuleOutput):

                # Get module id
                module_id = record_obj.parent.id
                if module_id in self.module_output_module_id_map:
                    temp_module_ouput_list = self.module_output_module_id_map[module_id]
                else:
                    temp_module_ouput_list = []
                    self.module_output_module_id_map[module_id] = temp_module_ouput_list

                # Add module obj to list
                temp_module_ouput_list.append(record_obj)

                port_id = record_obj.port_id
                if port_id in self.collection_module_output_port_id_map:
                    temp_module_ouput_list = self.collection_module_output_port_id_map[port_id]
                else:
                    temp_module_ouput_list = []
                    self.collection_module_output_port_id_map[port_id] = temp_module_ouput_list

                # Add module obj to list
                temp_module_ouput_list.append(record_obj)

                # Add collection module output obj to list for being imported
                self.collection_module_output_map[record_obj.id] = record_obj

            elif isinstance(record_obj, Certificate):

                # Get port id
                port_id = record_obj.parent.id
                if port_id in self.certificate_port_id_map:
                    temp_cert_list = self.certificate_port_id_map[port_id]
                else:
                    temp_cert_list = []
                    self.certificate_port_id_map[port_id] = temp_cert_list

                # Add port obj to list to be updated
                temp_cert_list.append(record_obj)

                # Add certificate obj to list for being imported
                self.certificate_map[record_obj.id] = record_obj

            elif isinstance(record_obj, Subnet):

                # Add screenshot obj to list for being imported
                self.subnet_map[record_obj.id] = record_obj

            # Add to overall mapping
            self.scan_obj_map[record_obj.id] = record_obj

    def get_port_number_list_from_scope(self) -> List[str]:
        """
        Get the list of port numbers from the original scan scope configuration.

        Returns the port numbers that were specified in the initial scan configuration,
        typically from a port bitmap or predefined port list.

        Returns:
            List[str]: List of port numbers as strings from the scan scope

        Example:
            >>> ports = scan_data.get_port_number_list_from_scope()
            >>> print(ports)
            ['22', '80', '443', '8080']
        """
        return list(self.port_number_list)

    def get_port_number_list_from_port_map(self) -> List[str]:
        """
        Get the list of port numbers from discovered ports in the port map.

        Returns port numbers for all ports that have been discovered during scanning,
        providing the actual ports found rather than just the scope.

        Returns:
            List[str]: List of unique port numbers as strings from discovered ports

        Example:
            >>> discovered_ports = scan_data.get_port_number_list_from_port_map()
            >>> print(discovered_ports)
            ['22', '80', '443', '3000', '8080']
        """
        port_number_list: Set[str] = set()
        for port_id in self.port_map:
            port_obj = self.port_map[port_id]
            if port_obj.port:
                port_number_list.add(str(port_obj.port))
        return list(port_number_list)

    def __init__(self, scan_data: Dict[str, Any], record_tags: Set[str] = None) -> None:
        """
        Initialize a new ScanData container with scan results and configuration.

        This constructor sets up all the internal data structures for organizing
        scan results and processes the initial scan data if provided.

        Args:
            scan_data (Dict[str, Any]): Dictionary containing scan configuration and results
                May include 'b64_port_bitmap' for port scope and 'obj_list' for scan objects
            record_tags (Set[str], optional): Set of tags to apply to all processed records
                Defaults to empty set if not provided

        Returns:
            None: Initializes the instance with processed scan data

        Example:
            >>> raw_data = {'obj_list': [host_data, port_data], 'b64_port_bitmap': 'base64data'}
            >>> scan_data = ScanData(raw_data, {RecordTag.SCOPE.value})
        """
        record_tags = record_tags or set()

        # Initialize all data structure collections
        self.scan_obj_list: List[Any] = []
        self.module_id: Optional[str] = None

        # Core object mappings - Maps object IDs to their respective objects
        # Universal object ID -> object mapping
        self.scan_obj_map: Dict[str, Any] = {}

        # Network infrastructure mappings
        # Subnet ID -> Subnet object
        self.subnet_map: Dict[str, 'Subnet'] = {}
        # Host ID -> Host object
        self.host_map: Dict[str, 'Host'] = {}
        # IP address -> Host ID
        self.host_ip_id_map: Dict[str, str] = {}

        # Host-Port relationship mappings
        # "IP:port"/"domain:port" -> {host_obj, port_obj}
        self.host_port_obj_map: Dict[str, Dict[str, Any]] = {}

        # Domain name mappings
        # Domain name -> Domain object
        self.domain_name_map: Dict[str, 'Domain'] = {}
        # Domain ID -> Domain object
        self.domain_map: Dict[str, 'Domain'] = {}
        # Host ID -> List of Domain objects
        self.domain_host_id_map: Dict[str, List['Domain']] = {}
        # "domain:port" -> (host_id, port_id)
        self.domain_port_id_map: Dict[str, Tuple[str, str]] = {}

        # Port mappings
        # Port ID -> Port object
        self.port_map: Dict[str, 'Port'] = {}
        # Port number -> Set of Host IDs
        self.port_host_map: Dict[str, Set[str]] = {}
        # Host ID -> List of Port objects
        self.host_id_port_map: Dict[str, List['Port']] = {}

        # Web component mappings
        # Component ID -> WebComponent object
        self.component_map: Dict[str, 'WebComponent'] = {}
        self.component_port_id_map: Dict[str, List['WebComponent']] = {
        }                # Port ID -> List of WebComponent objects
        # Component name -> List of Port IDs
        self.component_name_port_id_map: Dict[str, List[str]] = {}
        # Module name -> List of WebComponent objects
        self.module_name_component_map: Dict[str, List['WebComponent']] = {}

        # Web path and screenshot mappings
        # Path ID -> ListItem object
        self.path_map: Dict[str, 'ListItem'] = {}
        # Path hash -> List of Path IDs
        self.path_hash_id_map: Dict[str, List[str]] = {}
        # Screenshot ID -> Screenshot object
        self.screenshot_map: Dict[str, 'Screenshot'] = {}
        # Image hash -> List of Screenshot IDs
        self.screenshot_hash_id_map: Dict[str, List[str]] = {}

        # HTTP endpoint mappings
        # Endpoint ID -> HttpEndpoint object
        self.http_endpoint_map: Dict[str, 'HttpEndpoint'] = {}
        # Port ID -> List of HttpEndpoint objects
        self.http_endpoint_port_id_map: Dict[str, List['HttpEndpoint']] = {}
        # Path ID -> List of HttpEndpoint objects
        self.http_endpoint_path_id_map: Dict[str, List['HttpEndpoint']] = {}
        # Screenshot ID -> List of HttpEndpointData objects
        self.http_endpoint_data_screenshot_id_map: Dict[str, List['HttpEndpointData']] = {
        }

        # HTTP endpoint data mappings
        # EndpointData ID -> HttpEndpointData object
        self.http_endpoint_data_map: Dict[str, 'HttpEndpointData'] = {}
        # Endpoint ID -> List of HttpEndpointData objects
        self.endpoint_data_endpoint_id_map: Dict[str, List['HttpEndpointData']] = {
        }

        # Collection module mappings
        self.collection_module_map: Dict[str, 'CollectionModule'] = {
        }                  # Module ID -> CollectionModule object
        # Module name -> List of CollectionModule objects
        self.module_name_id_map: Dict[str, List['CollectionModule']] = {}
        # Output ID -> CollectionModuleOutput object
        self.collection_module_output_map: Dict[str,
                                                'CollectionModuleOutput'] = {}
        # Port ID -> List of outputs
        self.collection_module_output_port_id_map: Dict[str, List['CollectionModuleOutput']] = {
        }
        # Module ID -> List of outputs
        self.module_output_module_id_map: Dict[str,
                                               List['CollectionModuleOutput']] = {}

        # Vulnerability mappings
        # Vulnerability ID -> Vuln object
        self.vulnerability_map: Dict[str, 'Vuln'] = {}
        # Vulnerability name -> List of Vuln objects
        self.vulnerability_name_id_map: Dict[str, List['Vuln']] = {}

        # Certificate mappings
        # Certificate ID -> Certificate object
        self.certificate_map: Dict[str, 'Certificate'] = {}
        # Port ID -> List of Certificate objects
        self.certificate_port_id_map: Dict[str, List['Certificate']] = {}

        # Scope and configuration
        # List of port numbers from scan scope
        self.port_number_list: List[str] = []
        # Count of hosts processed
        self.host_count: int = 0

        # Additional module mappings
        # Module ID -> Module object
        self.module_map: Dict[str, Any] = {}
        self.component_name_module_map: Dict[str, List[Any]] = {
        }               # Component name -> List of modules

        # Process initial scan data
        # logging.getLogger(__name__).debug("Processing scan data\n %s" % scan_data)

        # Decode the port bitmap if present (defines scanning scope)
        if 'b64_port_bitmap' in scan_data and scan_data['b64_port_bitmap']:
            b64_port_bitmap = scan_data['b64_port_bitmap']
            if len(b64_port_bitmap) > 0:
                port_map = base64.b64decode(b64_port_bitmap)
                self.port_number_list = get_ports(port_map)

        # Process scan objects if present
        if 'obj_list' in scan_data and scan_data['obj_list']:
            obj_list = scan_data['obj_list']
            # Parse and organize the scan data
            self._process_data(obj_list, record_tags=record_tags)

        # Perform post-processing to build derived mappings
        self._post_process()


class Record:
    """
    Base class for all scan data records in the Waluigi framework.

    This abstract base class provides common functionality for all types of scan data
    objects including ID management, parent-child relationships, tagging, and 
    JSON serialization/deserialization capabilities.

    All specific record types (Host, Port, Domain, etc.) inherit from this class
    and implement their own data serialization methods.

    Attributes:
        id (str): Unique identifier for the record (auto-generated if not provided)
        parent (Record, optional): Parent record for hierarchical relationships
        scan_data (ScanData, optional): Reference to the containing scan data
        tags (Set[str]): Set of tags for categorizing the record
        collection_tool_instance_id (str, optional): ID of the tool that created this record

    Example:
        >>> record = Record(id="custom_id", parent=host_obj)
        >>> record.tags.add(RecordTag.SCOPE.value)
        >>> json_data = record.to_jsonable()
    """

    def __init__(self, id: Optional[str] = None, parent: Optional['Record'] = None,
                 collection_tool_instance_id: Optional[str] = None) -> None:
        """
        Initialize a new Record instance.

        Args:
            id (Optional[str]): Unique identifier for the record. If None, auto-generates UUID
            parent (Optional[Record]): Parent record for hierarchical relationships
            collection_tool_instance_id (Optional[str]): ID of the tool that created this record
        """
        self.id: str = id if id is not None else format(uuid.uuid4().int, 'x')
        self.parent: Optional['Record'] = parent
        self.scan_data: Optional['ScanData'] = None
        self.tags: Set[str] = set()
        self.collection_tool_instance_id: Optional[str] = collection_tool_instance_id

    def _data_to_jsonable(self) -> Optional[Dict[str, Any]]:
        """
        Convert record-specific data to JSON-serializable format.

        This method should be overridden by subclasses to provide their specific
        data serialization logic.

        Returns:
            Optional[Dict[str, Any]]: Record-specific data or None if no specific data
        """
        return None

    def to_jsonable(self) -> Dict[str, Any]:
        """
        Convert the complete record to a JSON-serializable dictionary.

        This method creates a standardized JSON representation of the record
        including metadata, parent relationships, and record-specific data.

        Returns:
            Dict[str, Any]: Complete JSON-serializable representation of the record

        Example:
            >>> record = Host()
            >>> record.ipv4_addr = "192.168.1.1"
            >>> json_data = record.to_jsonable()
            >>> print(json_data['type'])
            'host'
        """
        parent_dict: Optional[Dict[str, str]] = None
        if self.parent:
            parent_dict = {
                'type': str(self.parent.__class__.__name__).lower(),
                'id': self.parent.id
            }

        ret: Dict[str, Any] = {}
        ret['id'] = self.id
        ret['type'] = str(self.__class__.__name__).lower()
        ret['parent'] = parent_dict
        ret['collection_tool_instance_id'] = self.collection_tool_instance_id
        ret['data'] = self._data_to_jsonable()

        return ret

    def from_jsonsable(self, input_data_dict: Dict[str, Any]) -> None:
        """
        Populate the record from a JSON-serializable dictionary.

        This method should be overridden by subclasses to handle their specific
        data deserialization logic. The base implementation raises an exception
        to ensure proper implementation by subclasses.

        Args:
            input_data_dict (Dict[str, Any]): Dictionary containing record data

        Raises:
            Exception: Always raises exception if not overridden by subclass
        """
        logging.getLogger(__name__).error(
            f"from_jsonsable called on type: {type(self)}")
        raise Exception('No jsonable method defined for the child object.')

    @staticmethod
    def static_from_jsonsable(input_dict: Dict[str, Any], scan_data: Optional['ScanData'] = None,
                              record_tags: Set[str] = None) -> Optional['Record']:
        """
        Static factory method to create Record objects from JSON-serializable data.

        This method analyzes the input dictionary and creates the appropriate
        Record subclass instance based on the 'type' field. It handles all
        supported record types and properly sets up parent relationships.

        Args:
            input_dict (Dict[str, Any]): Dictionary containing record data with 'type' field
            scan_data (Optional[ScanData]): Reference to the containing scan data
            record_tags (Set[str], optional): Set of tags to apply to the created record

        Returns:
            Optional[Record]: Created Record subclass instance, or None if creation fails

        Raises:
            Exception: If record creation or data population fails

        Example:
            >>> data = {'type': 'host', 'id': 'host_1', 'data': {'ipv4_addr': '192.168.1.1'}}
            >>> host = Record.static_from_jsonsable(data)
            >>> print(type(host).__name__)
            'Host'
        """
        obj: Optional['Record'] = None
        record_tags_inst: Set[str] = set(record_tags or [])

        # Create record based on type
        try:
            obj_id = input_dict['id']
            record_data = input_dict['data']

            parent_id: Optional[str] = None
            if 'parent' in input_dict:
                parent_record = input_dict['parent']
                if parent_record:
                    parent_id = parent_record['id']

            if 'tags' in input_dict:
                record_tags_set = input_dict['tags']
                record_tags_inst.update(record_tags_set)

            record_type = input_dict['type']
            if record_type == 'host':
                obj = Host(id=obj_id)
            elif record_type == 'port':
                obj = Port(id=obj_id, parent_id=parent_id)
            elif record_type == 'domain':
                obj = Domain(id=obj_id, parent_id=parent_id)
            elif record_type == 'listitem':
                obj = ListItem(id=obj_id)
            elif record_type == 'httpendpoint':
                obj = HttpEndpoint(id=obj_id, parent_id=parent_id)
            elif record_type == 'httpendpointdata':
                obj = HttpEndpointData(
                    id=obj_id, parent_id=parent_id)
            elif record_type == 'screenshot':
                obj = Screenshot(id=obj_id)
            elif record_type == 'webcomponent':
                obj = WebComponent(id=obj_id, parent_id=parent_id)
            elif record_type == 'vuln':
                obj = Vuln(id=obj_id, parent_id=parent_id)
            elif record_type == 'collectionmodule':
                obj = CollectionModule(
                    id=obj_id, parent_id=parent_id)
            elif record_type == 'collectionmoduleoutput':
                obj = CollectionModuleOutput(id=obj_id, parent_id=parent_id)
            elif record_type == 'certificate':
                obj = Certificate(id=obj_id, parent_id=parent_id)
            elif record_type == 'subnet':
                obj = Subnet(id=obj_id)
            else:
                logging.getLogger(__name__).debug(
                    "Unknown record type: %s" % record_type)
                return

            # Populate data
            if obj:
                if 'collection_tool_instance_id' in input_dict:
                    obj.collection_tool_instance_id = input_dict['collection_tool_instance_id']

                obj.scan_data = scan_data
                obj.tags.update(record_tags_inst)
                obj.from_jsonsable(record_data)

        except Exception as e:
            logging.getLogger(__name__).error(traceback.format_exc())
            raise Exception('Invalid scan object:\n%s' % str(input_dict))

        return obj


class Tool(Record):
    """
    Represents a security scanning tool record.

    Simple record type for representing tools in the scanning framework.
    Inherits from Record base class and uses the tool ID as the record ID.

    Args:
        tool_id (str): Unique identifier for the tool

    Example:
        >>> tool = Tool("nmap_001")
        >>> print(tool.id)
        'nmap_001'
    """

    def __init__(self, tool_id: str) -> None:
        """Initialize a Tool record with the specified tool ID."""
        super().__init__(id=tool_id)


class Subnet(Record):
    """
    Represents a network subnet discovered during scanning.

    This record type stores subnet information including the network address
    and subnet mask, typically discovered through network reconnaissance.

    Attributes:
        subnet (str): Network address of the subnet
        mask (str): Subnet mask or CIDR notation

    Example:
        >>> subnet = Subnet()
        >>> subnet.subnet = "192.168.1.0"
        >>> subnet.mask = "24"
    """

    def __init__(self, id: Optional[str] = None) -> None:
        """
        Initialize a Subnet record.

        Args:
            id (Optional[str]): Unique identifier for the subnet record
        """
        super().__init__(id=id, parent=None)
        self.subnet: Optional[str] = None
        self.mask: Optional[str] = None

    def from_jsonsable(self, input_data_dict: Dict[str, Any]) -> None:
        """
        Populate subnet data from JSON dictionary.

        Args:
            input_data_dict (Dict[str, Any]): Dictionary containing 'subnet' and 'mask' keys

        Raises:
            Exception: If required subnet data is missing or invalid
        """
        try:
            self.subnet = input_data_dict['subnet']
            self.mask = input_data_dict['mask']
        except Exception as e:
            raise Exception('Invalid subnet object: %s' % str(e))


class Host(Record):
    """
    Represents a network host (computer/device) discovered during scanning.

    This is one of the core record types representing individual hosts on the network.
    Hosts can have IPv4 or IPv6 addresses and serve as parents for ports, domains,
    and other host-specific data.

    Attributes:
        ipv4_addr (Optional[str]): IPv4 address of the host
        ipv6_addr (Optional[str]): IPv6 address of the host (currently not fully supported)

    Example:
        >>> host = Host()
        >>> host.ipv4_addr = "192.168.1.100"
        >>> host.tags.add(RecordTag.SCOPE.value)
    """

    def __init__(self, id: Optional[str] = None) -> None:
        """
        Initialize a Host record.

        Args:
            id (Optional[str]): Unique identifier for the host record
        """
        super().__init__(id=id, parent=None)
        self.ipv4_addr: Optional[str] = None
        self.ipv6_addr: Optional[str] = None

    def _data_to_jsonable(self) -> Dict[str, str]:
        """
        Convert host-specific data to JSON-serializable format.

        Returns:
            Dict[str, str]: Dictionary containing IP address information
        """
        ret: Dict[str, str] = {}
        if self.ipv4_addr:
            ret['ipv4_addr'] = self.ipv4_addr
        elif self.ipv6_addr:
            ret['ipv6_addr'] = self.ipv6_addr
        return ret

    def from_jsonsable(self, input_data_dict: Dict[str, Any]) -> None:
        """
        Populate host data from JSON dictionary.

        Args:
            input_data_dict (Dict[str, Any]): Dictionary containing IP address data

        Raises:
            Exception: If IP address data is missing or invalid
        """
        try:
            if 'ipv4_addr' in input_data_dict:
                ipv4_addr_str = input_data_dict['ipv4_addr']
                self.ipv4_addr = str(netaddr.IPAddress(ipv4_addr_str))
            # IPv6 support is commented out in original code
            # elif 'ipv6_addr' in input_data_dict:
            #     ipv6_addr_str = input_data_dict['ipv6_addr']
            #     self.ipv6_addr = int(netaddr.IPAddress(input_data_dict['ipv6_addr_str']))
        except Exception as e:
            raise Exception('Invalid host object: %s' % str(e))


class Port(Record):
    """
    Represents a network port on a host discovered during scanning.

    This record type represents network services running on specific ports
    of hosts. Ports are children of Host records and can have associated
    services, vulnerabilities, and other port-specific data.

    Attributes:
        proto (int): Protocol number (e.g., 6 for TCP, 17 for UDP)
        port (str): Port number as string
        secure (bool): Whether the port uses secure/encrypted communication

    Example:
        >>> port = Port(parent_id="host_123")
        >>> port.port = "443"
        >>> port.proto = 6  # TCP
        >>> port.secure = True
    """

    def __init__(self, parent_id: Optional[str] = None, id: Optional[str] = None) -> None:
        """
        Initialize a Port record.

        Args:
            parent_id (Optional[str]): ID of the parent Host record
            id (Optional[str]): Unique identifier for the port record
        """
        super().__init__(id=id, parent=Host(id=parent_id))
        self.proto: Optional[int] = None
        self.port: Optional[str] = None
        self.secure: bool = False

    def _data_to_jsonable(self) -> Dict[str, Union[str, int, bool]]:
        """
        Convert port-specific data to JSON-serializable format.

        Returns:
            Dict[str, Union[str, int, bool]]: Dictionary containing port data
        """
        ret: Dict[str, Union[str, int, bool]] = {
            'port': self.port, 'proto': self.proto}
        if self.secure is not None:
            ret['secure'] = self.secure
        return ret

    def from_jsonsable(self, input_data_dict: Dict[str, Any]) -> None:
        """
        Populate port data from JSON dictionary.

        Args:
            input_data_dict (Dict[str, Any]): Dictionary containing port data

        Raises:
            Exception: If required port data is missing or invalid
        """
        try:
            self.port = str(input_data_dict['port'])
            self.proto = int(input_data_dict['proto'])
            if 'secure' in input_data_dict:
                secure_int = input_data_dict['secure']
                if secure_int == 1:
                    self.secure = True
                else:
                    self.secure = False
        except Exception as e:
            raise Exception('Invalid port object: %s' % str(e))


class Domain(Record):
    """
    Represents a domain name associated with a host discovered during scanning.

    This record type stores domain name information for hosts, typically discovered
    through DNS resolution, certificate analysis, or other reconnaissance methods.
    Domains are children of Host records and help map friendly names to IP addresses.

    Attributes:
        name (str): The domain name (e.g., "example.com", "www.example.com")

    Example:
        >>> domain = Domain(parent_id="host_123")
        >>> domain.name = "www.example.com"
        >>> domain.tags.add(RecordTag.SCOPE.value)
    """

    def __init__(self, parent_id: Optional[str] = None, id: Optional[str] = None) -> None:
        """
        Initialize a Domain record.

        Args:
            parent_id (Optional[str]): ID of the parent Host record
            id (Optional[str]): Unique identifier for the domain record
        """
        super().__init__(id=id, parent=Host(id=parent_id))
        self.name: Optional[str] = None

    def _data_to_jsonable(self) -> Dict[str, str]:
        """
        Convert domain-specific data to JSON-serializable format.

        Returns:
            Dict[str, str]: Dictionary containing domain name
        """
        return {'name': self.name}

    def from_jsonsable(self, input_data_dict: Dict[str, Any]) -> None:
        """
        Populate domain data from JSON dictionary.

        Args:
            input_data_dict (Dict[str, Any]): Dictionary containing domain name data

        Raises:
            Exception: If required domain data is missing or invalid
        """
        try:
            self.name = input_data_dict['name']
        except Exception as e:
            raise Exception('Invalid domain object: %s' % str(e))


class WebComponent(Record):
    """
    Represents a web technology/component detected on a network port.

    This record type stores information about web technologies, frameworks, servers,
    or other software components detected during web scanning. Components are children
    of Port records and help identify the technology stack of web services.

    Attributes:
        name (str): Name of the web component (e.g., "Apache", "nginx", "WordPress")
        version (Optional[str]): Version of the component if detected

    Example:
        >>> component = WebComponent(parent_id="port_123")
        >>> component.name = "Apache"
        >>> component.version = "2.4.41"
    """

    def __init__(self, parent_id: Optional[str] = None, id: Optional[str] = None) -> None:
        """
        Initialize a WebComponent record.

        Args:
            parent_id (Optional[str]): ID of the parent Port record
            id (Optional[str]): Unique identifier for the component record
        """
        super().__init__(id=id, parent=Port(id=parent_id))
        self.name: Optional[str] = None
        self.version: Optional[str] = None

    def _data_to_jsonable(self) -> Dict[str, str]:
        """
        Convert web component data to JSON-serializable format.

        Returns:
            Dict[str, str]: Dictionary containing component name and version
        """
        ret: Dict[str, str] = {'name': self.name}
        if self.version is not None:
            ret['version'] = self.version
        return ret

    def from_jsonsable(self, input_data_dict: Dict[str, Any]) -> None:
        """
        Populate web component data from JSON dictionary.

        Args:
            input_data_dict (Dict[str, Any]): Dictionary containing component data

        Raises:
            Exception: If required component data is missing or invalid
        """
        try:
            self.name = input_data_dict['name']
            if 'version' in input_data_dict:
                self.version = input_data_dict['version']
        except Exception as e:
            raise Exception('Invalid component object: %s' % str(e))


class Vuln(Record):
    """
    Represents a security vulnerability detected on a network port.

    This record type stores information about security vulnerabilities, weaknesses,
    or misconfigurations discovered during scanning. Vulnerabilities are children
    of Port records and may reference specific HTTP endpoints.

    Attributes:
        name (str): Name or identifier of the vulnerability (e.g., CVE-2021-44228)
        vuln_details (Optional[str]): Detailed description of the vulnerability
        endpoint_id (Optional[str]): ID of associated HTTP endpoint if applicable

    Example:
        >>> vuln = Vuln(parent_id="port_123")
        >>> vuln.name = "CVE-2021-44228"
        >>> vuln.vuln_details = "Log4Shell vulnerability in Apache Log4j"
    """

    def __init__(self, parent_id: Optional[str] = None, id: Optional[str] = None) -> None:
        """
        Initialize a Vuln record.

        Args:
            parent_id (Optional[str]): ID of the parent Port record
            id (Optional[str]): Unique identifier for the vulnerability record
        """
        super().__init__(id=id, parent=Port(id=parent_id))
        self.name: Optional[str] = None
        self.vuln_details: Optional[str] = None
        self.endpoint_id: Optional[str] = None

    def _data_to_jsonable(self) -> Dict[str, str]:
        """
        Convert vulnerability data to JSON-serializable format.

        Returns:
            Dict[str, str]: Dictionary containing vulnerability information
        """
        ret: Dict[str, str] = {'name': self.name}
        if self.vuln_details:
            ret['vuln_details'] = self.vuln_details
        if self.endpoint_id:
            ret['endpoint_id'] = self.endpoint_id
        return ret

    def from_jsonsable(self, input_data_dict: Dict[str, Any]) -> None:
        """
        Populate vulnerability data from JSON dictionary.

        Args:
            input_data_dict (Dict[str, Any]): Dictionary containing vulnerability data

        Raises:
            Exception: If required vulnerability data is missing or invalid
        """
        try:
            self.name = input_data_dict['name']
            if 'vuln_details' in input_data_dict:
                self.vuln_details = input_data_dict['vuln_details']
            if 'endpoint_id' in input_data_dict:
                self.endpoint_id = input_data_dict['endpoint_id']
        except Exception as e:
            raise Exception('Invalid vuln object: %s' % str(e))


class ListItem(Record):
    """
    Represents a web path or directory entry discovered during web scanning.

    This record type stores information about web paths, directories, or files
    discovered through directory brute forcing, crawling, or other web reconnaissance.
    ListItems are standalone records (no parent) and include path hashing for deduplication.

    Attributes:
        web_path (str): The web path or URI (e.g., "/admin", "/login.php")
        web_path_hash (str): SHA1 hash of the web path for deduplication

    Example:
        >>> item = ListItem()
        >>> item.web_path = "/admin"
        >>> item.web_path_hash = "sha1_hash_of_path"
    """

    def __init__(self, id: Optional[str] = None) -> None:
        """
        Initialize a ListItem record.

        Args:
            id (Optional[str]): Unique identifier for the path record
        """
        super().__init__(id=id)
        self.web_path: Optional[str] = None
        self.web_path_hash: Optional[str] = None

    def _data_to_jsonable(self) -> Dict[str, str]:
        """
        Convert path data to JSON-serializable format.

        Returns:
            Dict[str, str]: Dictionary containing path and hash information
        """
        return {'path': self.web_path,
                'path_hash': self.web_path_hash}

    def from_jsonsable(self, input_data_dict: Dict[str, Any]) -> None:
        """
        Populate path data from JSON dictionary.

        Args:
            input_data_dict (Dict[str, Any]): Dictionary containing path data

        Raises:
            Exception: If required path data is missing or invalid

        Note:
            If web_path is None, defaults to "/" and generates corresponding hash
        """
        try:
            self.web_path = input_data_dict['path']
            self.web_path_hash = input_data_dict['path_hash']
        except Exception as e:
            raise Exception('Invalid path object: %s' % str(e))

        # Default to root path if none specified
        if self.web_path is None:
            self.web_path = '/'
            hashobj = hashlib.sha1()
            hashobj.update(self.web_path.encode())
            path_hash = hashobj.digest()
            hex_str = binascii.hexlify(path_hash).decode()
            self.web_path_hash = hex_str


class Screenshot(Record):
    """
    Represents a screenshot captured from a web service or application.

    This record type stores screenshot data and metadata captured during web scanning.
    Screenshots are standalone records used to provide visual confirmation of web
    services and help with manual analysis of discovered targets.

    Attributes:
        screenshot (Optional[str]): Base64-encoded screenshot image data
        image_hash (Optional[str]): Hash of the screenshot for deduplication

    Example:
        >>> screenshot = Screenshot()
        >>> screenshot.image_hash = "sha256_hash_of_image"
        >>> screenshot.screenshot = "base64_encoded_image_data"
    """

    def __init__(self, id: Optional[str] = None) -> None:
        """
        Initialize a Screenshot record.

        Args:
            id (Optional[str]): Unique identifier for the screenshot record
        """
        super().__init__(id=id)
        self.screenshot: Optional[str] = None
        self.image_hash: Optional[str] = None

    def _data_to_jsonable(self) -> Dict[str, Optional[str]]:
        """
        Convert screenshot data to JSON-serializable format.

        Returns:
            Dict[str, Optional[str]]: Dictionary containing screenshot and hash data
        """
        return {'screenshot': self.screenshot,
                'image_hash': self.image_hash}

    def from_jsonsable(self, input_data_dict: Dict[str, Any]) -> None:
        """
        Populate screenshot data from JSON dictionary.

        Args:
            input_data_dict (Dict[str, Any]): Dictionary containing screenshot data

        Raises:
            Exception: If screenshot data is invalid
        """
        try:
            if 'screenshot' in input_data_dict:
                self.screenshot = input_data_dict['screenshot']

            if 'image_hash' in input_data_dict:
                self.image_hash = input_data_dict['image_hash']

        except Exception as e:
            raise Exception('Invalid screenshot object: %s' % str(e))


class HttpEndpoint(Record):
    """
    Represents an HTTP endpoint discovered on a network port.

    This record type represents a specific HTTP endpoint (URL path) on a web service.
    HttpEndpoints are children of Port records and reference web paths through web_path_id.
    They serve as containers for HTTP-specific data and analysis results.

    Attributes:
        web_path_id (Optional[str]): ID of the associated ListItem (web path)

    Example:
        >>> endpoint = HttpEndpoint(parent_id="port_443")
        >>> endpoint.web_path_id = "path_123"
        >>> url = endpoint.get_url()
    """

    def __init__(self, parent_id: Optional[str] = None, id: Optional[str] = None) -> None:
        """
        Initialize an HttpEndpoint record.

        Args:
            parent_id (Optional[str]): ID of the parent Port record
            id (Optional[str]): Unique identifier for the endpoint record
        """
        super().__init__(id=id, parent=Port(id=parent_id))
        self.web_path_id: Optional[str] = None

    def get_port(self) -> str:
        """
        Get the port number for this HTTP endpoint.

        Returns:
            str: Port number as string, or empty string if not found

        Example:
            >>> endpoint = HttpEndpoint(parent_id="port_443")
            >>> port_num = endpoint.get_port()
            >>> print(port_num)  # "443"
        """
        port_str: str = ''
        port_id = self.parent.id
        if port_id in self.scan_data.port_map:
            port_obj = self.scan_data.port_map[port_id]
            return port_obj.port
        return port_str

    def get_url(self) -> str:
        """
        Construct the complete URL for this HTTP endpoint.

        This method builds a full URL by combining host information, port details,
        security settings, and the web path. It handles both IP addresses and
        domain names when available.

        Returns:
            str: Complete URL for the endpoint (e.g., "https://example.com:443/admin")

        Example:
            >>> endpoint = HttpEndpoint()
            >>> url = endpoint.get_url()
            >>> print(url)  # "https://192.168.1.1:443/login"
        """
        port_id = self.parent.id
        host_ip: Optional[str] = None
        port_str: Optional[str] = None
        secure: Optional[bool] = None
        query_str: Optional[str] = None

        # Get port information
        if port_id in self.scan_data.port_map:
            port_obj = self.scan_data.port_map[port_id]
            port_str = port_obj.port
            secure = port_obj.secure

            # Get host IP from port's parent host
            if port_obj.parent.id in self.scan_data.host_map:
                host_obj = self.scan_data.host_map[port_obj.parent.id]
                if host_obj:
                    host_ip = host_obj.ipv4_addr

        # Check for domain names in endpoint data
        if self.id in self.scan_data.http_endpoint_map:
            http_endpoint_data_obj_list = self.scan_data.endpoint_data_endpoint_id_map[
                self.id]
            for http_endpoint_data_obj in http_endpoint_data_obj_list:
                if http_endpoint_data_obj.domain_id and http_endpoint_data_obj.domain_id in self.scan_data.domain_map:
                    domain_obj = self.scan_data.domain_map[http_endpoint_data_obj.domain_id]
                    if domain_obj:
                        host_ip = domain_obj.name
                        break

        # Get web path information
        if self.web_path_id in self.scan_data.path_map:
            path_obj = self.scan_data.path_map[self.web_path_id]
            query_str = path_obj.web_path

        # Construct the complete URL
        url_str = construct_url(
            host_ip, port_str, secure, query_str)

        return url_str

    def _data_to_jsonable(self) -> Dict[str, Optional[str]]:
        """
        Convert HTTP endpoint data to JSON-serializable format.

        Returns:
            Dict[str, Optional[str]]: Dictionary containing web path ID
        """
        ret: Dict[str, Optional[str]] = {'web_path_id': self.web_path_id}
        return ret

    def from_jsonsable(self, input_data_dict: Dict[str, Any]) -> None:
        """
        Populate HTTP endpoint data from JSON dictionary.

        Args:
            input_data_dict (Dict[str, Any]): Dictionary containing endpoint data

        Raises:
            Exception: If endpoint data is invalid
        """
        try:

            if 'web_path_id' in input_data_dict:
                self.web_path_id = input_data_dict['web_path_id']

        except Exception as e:
            raise Exception('Invalid http endpoint object: %s' % str(e))


class HttpEndpointData(Record):
    """
    Represents HTTP response data and metadata for an HTTP endpoint.

    This record type stores the actual HTTP response data, metadata, and analysis
    results for HTTP endpoints. HttpEndpointData are children of HttpEndpoint records
    and contain the detailed information gathered from HTTP requests.

    Attributes:
        title (Optional[str]): HTML title of the web page
        status (Optional[str]): HTTP response status code
        domain_id (Optional[str]): ID of associated domain if using domain name
        screenshot_id (Optional[str]): ID of associated screenshot
        last_modified (Optional[str]): Last-Modified header value
        fav_icon_hash (Optional[str]): Hash of the favicon for fingerprinting

    Example:
        >>> data = HttpEndpointData(parent_id="endpoint_123")
        >>> data.title = "Admin Login"
        >>> data.status = "200"
        >>> data.screenshot_id = "screenshot_456"
    """

    def __init__(self, parent_id: Optional[str] = None, id: Optional[str] = None) -> None:
        """
        Initialize an HttpEndpointData record.

        Args:
            parent_id (Optional[str]): ID of the parent HttpEndpoint record
            id (Optional[str]): Unique identifier for the endpoint data record
        """
        super().__init__(id=id, parent=HttpEndpoint(id=parent_id))
        self.title: Optional[str] = None
        self.status: Optional[str] = None
        self.domain_id: Optional[str] = None
        self.screenshot_id: Optional[str] = None
        self.last_modified: Optional[str] = None
        self.fav_icon_hash: Optional[str] = None

    def _data_to_jsonable(self) -> Dict[str, Optional[str]]:
        """
        Convert HTTP endpoint data to JSON-serializable format.

        Returns:
            Dict[str, Optional[str]]: Dictionary containing HTTP response metadata
        """
        ret: Dict[str, Optional[str]] = {
            'title': self.title, 'status': self.status}

        if self.last_modified is not None:
            ret['last_modified'] = self.last_modified

        if self.domain_id is not None:
            ret['domain_id'] = self.domain_id

        if self.screenshot_id is not None:
            ret['screenshot_id'] = self.screenshot_id

        if self.fav_icon_hash is not None:
            ret['fav_icon_hash'] = self.fav_icon_hash

        return ret

    def get_url(self) -> str:
        """
        Construct the full URL for this HTTP endpoint data.

        This method traverses the data relationships to build a complete URL by:
        1. Finding the associated HTTP endpoint and port information
        2. Resolving the host IP address or domain name
        3. Extracting path and query parameters
        4. Constructing the final URL string

        Returns:
            str: Complete URL string (e.g., "https://example.com:443/path?query=value")

        Example:
            >>> endpoint_data = HttpEndpointData()
            >>> url = endpoint_data.get_url()
            >>> print(url)  # "https://192.168.1.1:8080/api/v1"
        """
        port_id = None
        host_ip = None
        port_str = None
        secure = None
        query_str = None

        if self.parent.id in self.scan_data.http_endpoint_map:
            http_endpoint_obj = self.scan_data.http_endpoint_map[self.parent.id]
            port_id = http_endpoint_obj.parent.id
            web_path_id = http_endpoint_obj.web_path_id

            if web_path_id in self.scan_data.path_map:
                path_obj = self.scan_data.path_map[web_path_id]
                query_str = path_obj.web_path

        if port_id and port_id in self.scan_data.port_map:
            port_obj = self.scan_data.port_map[port_id]
            port_str = port_obj.port
            secure = port_obj.secure

            if port_obj.parent.id in self.scan_data.host_map:
                host_obj = self.scan_data.host_map[port_obj.parent.id]
                if host_obj:
                    host_ip = host_obj.ipv4_addr

        if self.domain_id and self.domain_id in self.scan_data.domain_map:
            domain_obj = self.scan_data.domain_map[self.domain_id]
            if domain_obj:
                host_ip = domain_obj.name

        url_str = construct_url(
            host_ip, port_str, secure, query_str)

        return url_str

    def from_jsonsable(self, input_data_dict: Dict[str, Any]) -> None:
        """
        Deserialize HTTP endpoint data from a JSON-compatible dictionary.

        Args:
            input_data_dict (Dict[str, Any]): Dictionary containing endpoint data with keys:
                - title (optional): Page title
                - status (optional): HTTP status code
                - last_modified (optional): Last modification timestamp
                - screenshot_id (optional): Associated screenshot ID
                - domain_id (optional): Associated domain ID
                - fav_icon_hash (optional): Favicon hash

        Raises:
            Exception: If deserialization fails with invalid data

        Example:
            >>> data = {"title": "Example Page", "status": 200}
            >>> endpoint_data.from_jsonsable(data)
        """
        try:

            self.screenshot_id = None
            self.last_modified = None
            self.domain_id = None
            self.fav_icon_hash = None

            if 'title' in input_data_dict:
                self.title = input_data_dict['title']

            if 'status' in input_data_dict:
                self.status = input_data_dict['status']

            if 'last_modified' in input_data_dict:
                self.last_modified = input_data_dict['last_modified']

            if 'screenshot_id' in input_data_dict:
                self.screenshot_id = input_data_dict['screenshot_id']

            if 'domain_id' in input_data_dict:
                self.domain_id = input_data_dict['domain_id']

            if 'fav_icon_hash' in input_data_dict and input_data_dict['fav_icon_hash']:
                self.fav_icon_hash = input_data_dict['fav_icon_hash']

        except Exception as e:
            raise Exception('Invalid http endpoint data object: %s' % str(e))


class CollectionModule(Record):
    """
    Represents a collection module for organizing and executing scanning tools.

    A collection module defines a set of tools to be executed together, with
    bindings to specific components and the ability to track outputs. It serves
    as a container for related scanning operations.

    Attributes:
        name (Optional[str]): Name of the collection module
        args (Optional[str]): Arguments passed to the module
        bindings (Optional[List[str]]): List of component IDs this module is bound to
        outputs (Optional[List[str]]): List of output component IDs generated by this module

    Example:
        >>> module = CollectionModule(parent_id="tool_123")
        >>> module.name = "web_scan"
        >>> module.args = "--deep-scan"
        >>> module.bindings = ["web_component_1", "web_component_2"]
    """

    def __init__(self, parent_id: Optional[str] = None, id: Optional[str] = None):
        """
        Initialize a new CollectionModule.

        Args:
            parent_id (Optional[str]): ID of the parent Tool object
            id (Optional[str]): Unique identifier for this module
        """
        super().__init__(id=id, parent=Tool(parent_id))

        self.name: Optional[str] = None
        self.args: Optional[str] = None
        self.bindings: Optional[List[str]] = None
        self.outputs: Optional[List[str]] = None

    def _data_to_jsonable(self) -> Dict[str, Any]:
        """
        Convert the collection module to a JSON-serializable dictionary.

        Returns:
            Dict[str, Any]: Dictionary containing module name and arguments

        Example:
            >>> module = CollectionModule()
            >>> module.name = "nmap_scan"
            >>> module.args = "-sS -O"
            >>> data = module._data_to_jsonable()
            >>> print(data)  # {"name": "nmap_scan", "args": "-sS -O"}
        """
        ret = {'name': self.name, 'args': self.args}
        return ret

    def get_output_components(self) -> List['WebComponent']:
        """
        Retrieve all output components generated by this collection module.

        Returns:
            List[WebComponent]: List of WebComponent objects that were outputs of this module

        Example:
            >>> module = CollectionModule()
            >>> components = module.get_output_components()
            >>> for comp in components:
            ...     print(f"Component: {comp.name}")
        """
        output_components = []

        component_arr = self.outputs
        if component_arr is None:
            return output_components

        component_map = self.scan_data.component_map
        for component_id in component_arr:
            if component_id in component_map:
                component_obj = component_map[component_id]
                output_components.append(component_obj)

        return output_components

    def get_host_port_obj_map(self) -> Dict[str, Dict[str, 'Port']]:
        """
        Build a mapping of host IDs to port objects based on module bindings.

        This method traverses the module's component bindings to identify all
        ports associated with those components, creating a nested dictionary
        structure for efficient access.

        Returns:
            Dict[str, Dict[str, Port]]: Nested dictionary mapping:
                - Outer key: Host ID
                - Inner key: Port number (as string)
                - Value: Port object

        Example:
            >>> module = CollectionModule()
            >>> host_port_map = module.get_host_port_obj_map()
            >>> for host_id, ports in host_port_map.items():
            ...     print(f"Host {host_id}: {list(ports.keys())}")
        """
        host_port_obj_map = {}

        component_arr = self.bindings
        if component_arr is None:
            return host_port_obj_map

        component_map = self.scan_data.component_map
        component_name_port_id_map = self.scan_data.component_name_port_id_map

        # Get the module binding and see if there are any ports mapped to this component name
        for component_id in component_arr:
            if component_id in component_map:

                component_obj = component_map[component_id]
                component_key = component_obj.name

                if component_key in component_name_port_id_map:
                    port_id_list = component_name_port_id_map[component_key]
                    for port_id in port_id_list:
                        if port_id in self.scan_data.port_map:
                            update_host_port_obj_map(
                                self.scan_data, port_id, host_port_obj_map)
                else:
                    logging.getLogger(__name__).debug(
                        "Component key not found in component name port id map: %s" % component_key)
            else:
                logging.getLogger(__name__).debug(
                    "Component id not found in component map: %s" % component_id)

        return host_port_obj_map

    def from_jsonsable(self, input_data_dict: Dict[str, Any]) -> None:
        """
        Deserialize collection module data from a JSON-compatible dictionary.

        Args:
            input_data_dict (Dict[str, Any]): Dictionary containing module data with keys:
                - name (required): Module name
                - args (required): Module arguments
                - bindings (optional): List of component binding IDs
                - outputs (optional): List of output component IDs

        Raises:
            Exception: If deserialization fails due to missing required fields

        Example:
            >>> data = {
            ...     "name": "web_scanner",
            ...     "args": "--verbose",
            ...     "bindings": ["comp_1", "comp_2"]
            ... }
            >>> module.from_jsonsable(data)
        """
        try:

            self.name = str(input_data_dict['name'])
            self.args = str(input_data_dict['args'])

            if 'bindings' in input_data_dict:
                self.bindings = input_data_dict['bindings']
            if 'outputs' in input_data_dict:
                self.outputs = input_data_dict['outputs']

        except Exception as e:
            raise Exception('Invalid collection module object: %s' % str(e))


class CollectionModuleOutput(Record):
    """
    Represents output data generated by a collection module.

    This class stores the output produced by a collection module execution,
    including the raw data and associated port information for context.

    Attributes:
        data (Optional[str]): Raw output data from the module execution
        port_id (Optional[str]): ID of the port associated with this output

    Example:
        >>> output = CollectionModuleOutput(parent_id="module_123")
        >>> output.output = "Port 80 is open"
        >>> output.port_id = "port_456"
    """

    def __init__(self, parent_id: Optional[str] = None, id: Optional[str] = None):
        """
        Initialize a new CollectionModuleOutput.

        Args:
            parent_id (Optional[str]): ID of the parent CollectionModule
            id (Optional[str]): Unique identifier for this output
        """
        super().__init__(id=id, parent=CollectionModule(id=parent_id))

        self.output: Optional[str] = None
        self.port_id: Optional[str] = None

    def _data_to_jsonable(self) -> Dict[str, Any]:
        """
        Convert the collection module output to a JSON-serializable dictionary.

        Returns:
            Dict[str, Any]: Dictionary containing output data and port ID

        Example:
            >>> output = CollectionModuleOutput()
            >>> output.output = "Service detected: HTTP"
            >>> output.port_id = "port_80"
            >>> data = output._data_to_jsonable()
            >>> print(data)  # {"output": "Service detected: HTTP", "port_id": "port_80"}
        """
        ret = {'output': self.output, 'port_id': self.port_id}
        return ret

    def from_jsonsable(self, input_data_dict: Dict[str, Any]) -> None:
        """
        Deserialize collection module output from a JSON-compatible dictionary.

        Args:
            input_data_dict (Dict[str, Any]): Dictionary containing output data with keys:
                - output (required): Raw output data string
                - port_id (required): Associated port ID

        Raises:
            Exception: If deserialization fails due to missing required fields

        Example:
            >>> data = {"output": "HTTP service detected", "port_id": "port_123"}
            >>> output.from_jsonsable(data)
        """
        try:

            self.output = str(input_data_dict['output'])
            self.port_id = str(input_data_dict['port_id'])

        except Exception as e:
            raise Exception(
                'Invalid collection module output object: %s' % str(e))


class Certificate(Record):
    """
    Represents an SSL/TLS certificate discovered during scanning.

    This class stores certificate information including issuer details,
    validity periods, fingerprints, and associated domain names.

    Attributes:
        issuer (Optional[str]): Certificate issuer name
        issued (Optional[int]): Certificate issued timestamp (Unix epoch)
        expires (Optional[int]): Certificate expiration timestamp (Unix epoch)
        fingerprint_hash (Optional[str]): Certificate fingerprint hash
        domain_name_id_map (Dict[str, str]): Mapping of domain names to their IDs
        domain_id_list (List[str]): List of domain IDs associated with this certificate

    Example:
        >>> cert = Certificate(parent_id="port_443")
        >>> cert.issuer = "Let's Encrypt Authority X3"
        >>> cert.issued = 1609459200  # 2021-01-01
        >>> cert.expires = 1640995200  # 2022-01-01
        >>> cert.fingerprint_hash = "a1b2c3d4e5f6..."
    """

    def __init__(self, parent_id: Optional[str] = None, id: Optional[str] = None):
        """
        Initialize a new Certificate.

        Args:
            parent_id (Optional[str]): ID of the parent Port object
            id (Optional[str]): Unique identifier for this certificate
        """
        super().__init__(id=id, parent=Port(id=parent_id))

        self.issuer: Optional[str] = None
        self.issued: Optional[int] = None
        self.expires: Optional[int] = None
        self.fingerprint_hash: Optional[str] = None
        self.domain_name_id_map: Dict[str, str] = {}
        self.domain_id_list: List[str] = []

    def _data_to_jsonable(self) -> Dict[str, Any]:
        """
        Convert the certificate to a JSON-serializable dictionary.

        Returns:
            Dict[str, Any]: Dictionary containing all certificate data including
                           issuer, validity dates, fingerprint, and associated domains

        Example:
            >>> cert = Certificate()
            >>> cert.issuer = "DigiCert"
            >>> cert.issued = 1609459200
            >>> data = cert._data_to_jsonable()
            >>> print(data["issuer"])  # "DigiCert"
        """
        ret = {'issuer': self.issuer}
        ret['issued'] = self.issued
        ret['expires'] = self.expires
        ret['fingerprint_hash'] = self.fingerprint_hash
        ret['domain_id_list'] = list(self.domain_name_id_map.values())
        return ret

    def from_jsonsable(self, input_data_dict: Dict[str, Any]) -> None:
        """
        Deserialize certificate data from a JSON-compatible dictionary.

        Args:
            input_data_dict (Dict[str, Any]): Dictionary containing certificate data with keys:
                - issuer (required): Certificate issuer name
                - issued (required): Issued timestamp as integer
                - expires (required): Expiration timestamp as integer
                - fingerprint_hash (required): Certificate fingerprint
                - domain_id_list (required): List of associated domain IDs

        Raises:
            Exception: If deserialization fails due to invalid data format

        Example:
            >>> data = {
            ...     "issuer": "Let's Encrypt",
            ...     "issued": 1609459200,
            ...     "expires": 1640995200,
            ...     "fingerprint_hash": "abc123...",
            ...     "domain_id_list": ["domain_1", "domain_2"]
            ... }
            >>> cert.from_jsonsable(data)
        """
        try:
            self.issuer = input_data_dict['issuer']
            self.issued = int(input_data_dict['issued'])
            self.expires = int(input_data_dict['expires'])
            self.fingerprint_hash = input_data_dict['fingerprint_hash']
            self.domain_id_list = input_data_dict['domain_id_list']

        except Exception as e:
            raise Exception('Invalid certificate object: %s' % str(e))

    def add_domain(self, host_id: str, domain_str: str, collection_tool_instance_id: str) -> Optional['Domain']:
        """
        Add a domain name to the certificate's domain list.

        This method creates a new Domain record for domain names found in SSL/TLS
        certificates. It filters out wildcard domains and IP addresses.

        Args:
            host_id (str): ID of the host associated with this certificate
            domain_str (str): Domain name to add
            collection_tool_instance_id (str): ID of the tool that discovered this domain

        Returns:
            Optional[Domain]: Created Domain object, or None if domain was filtered out

        Example:
            >>> cert = Certificate()
            >>> domain = cert.add_domain("host_123", "example.com", "tool_456")
            >>> print(domain.name if domain else "Filtered out")
        """
        # Filter out wildcard certificates
        if "*." in domain_str:
            return None

        # Filter out IP addresses
        try:
            int(netaddr.IPAddress(domain_str))
            return None
        except:
            pass

        # Create new domain if not already present
        if domain_str not in self.domain_name_id_map:
            domain_obj = Domain(parent_id=host_id)
            domain_obj.collection_tool_instance_id = collection_tool_instance_id
            domain_obj.name = domain_str

            self.domain_name_id_map[domain_str] = domain_obj.id
            return domain_obj
