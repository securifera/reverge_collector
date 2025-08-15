"""
Scan Utilities Module.

This module provides essential utility classes and functions for the Waluigi framework's
scanning operations. It includes thread pool management, process execution wrappers,
network utilities, file parsing functions, and other common functionality needed
across different scanning tools.

The module supports:
    - Thread pool execution with callback handling and error tracking  
    - Process execution wrappers with stream capture and monitoring
    - Network utilities for URL construction and port management
    - JSON blob file parsing for tool output processing
    - Directory initialization and file system operations
    - Performance timing and execution monitoring
    - Domain validation and IP address checking

Classes:
    ThreadExecutorWrapper: Enhanced thread pool executor with callback management
    ProcessStreamReader: Thread-based stream reader for process output capture

Functions:
    execution_time: Decorator for measuring function execution time
    get_url_port: Extract port number from URL strings
    construct_url: Build URLs from components with proper protocol handling
    get_ports: Extract port numbers from byte array representations
    set_bit: Set specific bits in byte arrays for port mapping
    get_port_byte_array: Convert port lists to byte array representation
    check_domain: Validate domain names and filter invalid entries
    init_tool_folder: Create and initialize tool output directories
    process_wrapper: Execute processes with stream capture and monitoring
    parse_json_blob_file: Parse JSON objects from multi-object files

Global Variables:
    NOT_WHITESPACE: Regex pattern for finding non-whitespace characters
    custom_user_agent: Standard user agent string for HTTP requests
    executor: Global thread pool executor instance

Example:
    Basic thread pool usage::
    
        # Submit tasks to thread pool
        future = executor.submit(some_function, arg1, arg2)
        result = future.result()
        
        # Execute process with output capture
        result = process_wrapper(['nmap', '-sn', '192.168.1.0/24'], 
                               store_output=True)
        
        # Parse JSON output files
        objects = parse_json_blob_file('/path/to/output.json')

Note:
    This module provides the core infrastructure for concurrent execution,
    process management, and data processing across all Waluigi scanning tools.
    The global executor instance is shared across the framework for efficient
    resource management.

.. moduleauthor:: Waluigi Framework Team
.. version:: 1.0.0
"""

from functools import wraps
import math
import os
import validators
import re
import threading
import time
import traceback
import netaddr
import logging
import socket

from json import JSONDecoder, JSONDecodeError
from threading import Thread
from queue import Queue
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, Future
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional, Union, Callable, Set


# Regex pattern for finding non-whitespace characters in JSON parsing
NOT_WHITESPACE = re.compile(r'\S')

# Standard user agent string for HTTP requests across the framework
custom_user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.3"


class ThreadExecutorWrapper:
    """
    Enhanced thread pool executor with callback management and error tracking.

    This class wraps the standard ThreadPoolExecutor to provide additional
    functionality including task tracking, automatic callback handling,
    and comprehensive error logging. It maintains a mapping of futures to
    task IDs for better monitoring and debugging capabilities.

    The wrapper provides:
        - Automatic task ID assignment and tracking
        - Exception handling and logging for all submitted tasks
        - Thread-safe operations with proper locking
        - Graceful shutdown capabilities
        - Detailed logging for debugging and monitoring

    Attributes:
        executor (ThreadPoolExecutor): The underlying thread pool executor
        futures_map (Dict[Future, int]): Mapping of futures to task IDs
        lock (threading.Lock): Thread synchronization lock
        task_counter (int): Incremental counter for task ID assignment

    Methods:
        submit: Submit a callable for execution with automatic tracking
        shutdown: Gracefully shutdown the executor
        _internal_callback: Internal callback for future completion handling

    Example:
        >>> wrapper = ThreadExecutorWrapper(max_workers=20)
        >>> future = wrapper.submit(some_function, arg1, arg2)
        >>> result = future.result()
        >>> wrapper.shutdown(wait=True)

    Note:
        This wrapper automatically adds completion callbacks to all submitted
        futures for logging and error handling. Task IDs are assigned sequentially
        for tracking purposes.
    """

    def __init__(self, max_workers: int = 10) -> None:
        """
        Initialize the thread executor wrapper with specified worker count.

        Args:
            max_workers (int): Maximum number of worker threads in the pool.
                Defaults to 10 for balanced performance and resource usage.
        """
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.futures_map: Dict[Future, int] = {}
        self.lock = threading.Lock()
        self.task_counter = 0

    def _internal_callback(self, future: Future) -> None:
        """
        Internal callback function for handling future completion.

        This method is automatically called when a submitted future completes,
        either successfully or with an exception. It handles cleanup of the
        futures mapping and provides comprehensive logging for debugging.

        Args:
            future (Future): The completed future object to process.

        Note:
            This method is called automatically by the threading system and
            should not be invoked directly by user code.
        """
        with self.lock:
            task_id = self.futures_map.pop(future, None)

        if task_id is None:
            logging.getLogger(__name__).warning("Future not found in the map.")
            return

        try:
            result = future.result()
            logging.getLogger(__name__).debug(
                f"Task {task_id}/{len(self.futures_map)} completed")
        except Exception as e:
            tb = traceback.format_exc()
            logging.getLogger(__name__).debug(
                f"Task {task_id} raised an exception: {e}")
            logging.getLogger(__name__).debug(f"Traceback:\n{tb}")

    def submit(self, fn: Callable, *args, **kwargs) -> Future:
        """
        Submit a callable for execution in the thread pool.

        This method submits a callable for execution and automatically assigns
        a task ID for tracking purposes. The future is registered with an
        internal callback for completion handling and logging.

        Args:
            fn (Callable): The callable to execute in the thread pool.
            *args: Positional arguments to pass to the callable.
            **kwargs: Keyword arguments to pass to the callable.

        Returns:
            Future: A Future object representing the execution of the callable.

        Example:
            >>> future = wrapper.submit(requests.get, 'http://example.com')
            >>> response = future.result()

        Note:
            The returned future will have an automatic callback attached for
            logging and error handling. Task IDs are assigned sequentially.
        """
        with self.lock:
            task_id = self.task_counter
            self.task_counter += 1

        future = self.executor.submit(fn, *args, **kwargs)
        with self.lock:
            self.futures_map[future] = task_id
        future.add_done_callback(self._internal_callback)

        return future

    def shutdown(self, wait: bool = True) -> None:
        """
        Shutdown the thread pool executor.

        Initiates a clean shutdown of the underlying ThreadPoolExecutor,
        optionally waiting for all currently executing tasks to complete.

        Args:
            wait (bool): If True, wait for all pending futures to finish
                before returning. If False, return immediately after
                initiating shutdown. Defaults to True.

        Example:
            >>> wrapper.shutdown(wait=True)  # Wait for all tasks
            >>> wrapper.shutdown(wait=False)  # Immediate shutdown

        Note:
            After shutdown, no new tasks can be submitted to the executor.
            It's good practice to call this method when the executor is
            no longer needed to properly clean up resources.
        """
        self.executor.shutdown(wait=wait)
        logging.getLogger(__name__).debug("Executor has been shut down.")


def execution_time(f: Callable) -> Callable:
    """
    Decorator for measuring and logging function execution time.

    This decorator wraps a function to automatically measure its execution
    time and log the results. It's useful for performance monitoring and
    optimization of scanning operations.

    Args:
        f (Callable): The function to wrap with timing measurement.

    Returns:
        Callable: The wrapped function with timing functionality.

    Example:
        >>> @execution_time
        ... def slow_function():
        ...     time.sleep(2)
        ...     return "done"
        >>> result = slow_function()  # Logs execution time

    Note:
        Execution time is logged at DEBUG level with the function name
        and duration in seconds.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        start_time = int(time.time())
        result = f(*args, **kwargs)
        end_time = int(time.time())
        logging.getLogger(__name__).debug(
            f"Execution time of '{f.__name__}': {end_time-start_time} seconds")
        return result
    return wrapper


def get_url_port(url: str) -> Optional[int]:
    """
    Extract port number from a URL string.

    This function parses a URL and extracts the port number, applying
    default ports for common protocols (80 for HTTP, 443 for HTTPS)
    when no explicit port is specified.

    Args:
        url (str): The URL string to parse for port information.

    Returns:
        Optional[int]: The port number if successfully extracted,
            or None if the URL is invalid or parsing fails.

    Example:
        >>> get_url_port('https://example.com:8443/path')
        8443
        >>> get_url_port('http://example.com')
        80
        >>> get_url_port('https://example.com')
        443

    Note:
        Default ports are applied based on protocol scheme:
        - HTTP: port 80
        - HTTPS: port 443
    """
    port_int = None
    try:
        u = urlparse(url)
        port_int = 80
        if u.port is not None:
            port_int = u.port
        else:
            if u.scheme == 'https':
                port_int = 443
        return port_int
    except Exception as e:
        logging.getLogger(__name__).error("Invalid URL")
        return port_int


def construct_url(target_str: str, port: int, secure: bool,
                  query_str: Optional[str] = None) -> Optional[str]:
    """
    Construct a complete URL from individual components.

    This function builds a properly formatted URL from target hostname,
    port number, security flag, and optional query string. It handles
    protocol selection and port inclusion based on standard conventions.

    Args:
        target_str (str): The target hostname or IP address.
        port (int): The port number for the connection.
        secure (bool): Whether to use HTTPS (True) or HTTP (False).
        query_str (Optional[str]): Optional query string to append.

    Returns:
        Optional[str]: The constructed URL string, or None if required
            parameters are missing or invalid.

    Example:
        >>> construct_url('example.com', 8080, False)
        'http://example.com:8080'
        >>> construct_url('example.com', 443, True, '/api/v1')
        'https://example.com/api/v1'

    Note:
        Standard ports (80 for HTTP, 443 for HTTPS) are omitted from
        the URL for cleaner formatting. The secure flag overrides port
        443 to use HTTPS regardless of the secure parameter.
    """
    if target_str is None or port is None or secure is None:
        return None

    port_str = str(port).strip()
    add_port_flag = True
    url = "http"

    if secure or port_str == '443':
        url += "s"
        if port_str == '443':
            add_port_flag = False
    elif port_str == '80':
        add_port_flag = False

    url += "://" + target_str
    if add_port_flag:
        url += ":" + port_str

    if query_str:
        url += query_str

    try:
        validators.url(url)
        return url
    except Exception as e:
        logging.getLogger(__name__).debug(
            f"Invalid URL constructed: {url}. Skipping scan queue. Error: {e}")
        return None


def get_ports(byte_array: bytearray) -> List[str]:
    """
    Extract port numbers from a byte array representation.

    This function converts a byte array where each bit represents a port
    number back to a list of port strings. It's used for decoding port
    mappings stored in compact binary format.

    Args:
        byte_array (bytearray): Byte array with port bits set.

    Returns:
        List[str]: List of port numbers as strings.

    Example:
        >>> ports = get_ports(port_byte_array)
        >>> print(ports)  # ['22', '80', '443']

    Note:
        This function is the inverse operation of set_bit() and is used
        for decoding port ranges stored in binary format.
    """
    port_list = []
    if byte_array:
        for i in range(0, len(byte_array)):
            current_byte = byte_array[i]
            for j in range(8):
                mask = 1 << j
                if current_byte & mask:
                    port_list.append(str(j + (i*8)))
    return port_list


def set_bit(num: int, byte_array: bytearray) -> None:
    """
    Set a specific bit in a byte array to represent a port number.

    This function sets the bit corresponding to a port number in a byte
    array, enabling compact storage of port ranges and lists.

    Args:
        num (int): The port number (bit position) to set.
        byte_array (bytearray): The byte array to modify.

    Example:
        >>> byte_array = bytearray(8192)
        >>> set_bit(80, byte_array)  # Set bit for port 80
        >>> set_bit(443, byte_array)  # Set bit for port 443

    Note:
        The byte array should be large enough to accommodate the highest
        port number. Standard size is 8192 bytes for ports 0-65535.
    """
    byte_num = math.floor(num / 8)
    bit_pos = num % 8

    if byte_num < len(byte_array):
        current_byte = byte_array[byte_num]
        byte_array[byte_num] = current_byte | (1 << bit_pos)


def get_port_byte_array(port_list: str) -> bytearray:
    """
    Convert a port list string to byte array representation.

    This function parses a port list string (supporting individual ports,
    ranges, and comma/space separation) and converts it to a compact byte
    array representation where each bit represents a port.

    Args:
        port_list (str): Port list string (e.g., "22,80,443" or "1000-2000").

    Returns:
        bytearray: Byte array with bits set for each specified port.

    Example:
        >>> byte_array = get_port_byte_array("22,80,443,8000-8010")
        >>> ports = get_ports(byte_array)  # Convert back to verify

    Note:
        Supports multiple formats:
        - Individual ports: "80,443"
        - Port ranges: "8000-8010"
        - Mixed: "22,80,443,8000-8010"
        - Space or comma delimited
    """

    port_map_bytes = bytearray(8192)
    if len(port_list) > 0:
        # Determine split delimiter (comma or space)
        split_delim = None
        if "," in port_list:
            split_delim = ","
        elif " " in port_list:
            split_delim = " "

        # Split port list or use as single item
        port_arr = [port_list]
        if split_delim:
            port_arr = port_list.split(split_delim)

        # Process each port or port range
        for port_inst in port_arr:
            port_range_arr = port_inst.split("-")
            if len(port_range_arr) == 1:
                # Single port
                set_bit(int(port_range_arr[0]), port_map_bytes)
            else:
                # Port range
                start = int(port_range_arr[0])
                end = int(port_range_arr[1])
                for port in range(start, end + 1):
                    set_bit(int(port), port_map_bytes)

    return port_map_bytes


def check_domain(domain_str: str) -> Optional[str]:
    """
    Validate and filter domain names for processing.

    This function checks if a domain string is valid for processing,
    filtering out wildcards and IP addresses which should be handled
    differently in the scanning workflow.

    Args:
        domain_str (str): The domain string to validate.

    Returns:
        Optional[str]: The domain string if valid, None if it should be filtered.

    Example:
        >>> check_domain('example.com')
        'example.com'
        >>> check_domain('*.example.com')  # Wildcard
        None
        >>> check_domain('192.168.1.1')  # IP address
        None

    Note:
        Filters out:
        - Wildcard domains (containing "*.")
        - IP addresses (detected using netaddr)
    """
    # Filter out wildcard domains
    if "*." in domain_str:
        return None

    # Filter out IP addresses
    try:
        ip_addr_check = int(netaddr.IPAddress(domain_str))
        return None
    except:
        pass

    return domain_str


def init_tool_folder(tool_name: str, desc: str, scan_id: str) -> str:
    """
    Initialize and create tool output directory structure.

    This function creates the necessary directory structure for storing
    tool outputs, organized by scan ID and tool name. It ensures proper
    permissions are set for the created directories.

    Args:
        tool_name (str): Name of the tool (e.g., 'nmap', 'nuclei').
        desc (str): Description or subdirectory (e.g., 'outputs', 'inputs').
        scan_id (str): Unique identifier for the scan session.

    Returns:
        str: The full path to the created directory.

    Example:
        >>> dir_path = init_tool_folder('nmap', 'outputs', 'scan_123')
        >>> print(dir_path)
        /current/working/dir/scan_123/nmap-outputs

    Note:
        Directory structure: {cwd}/{scan_id}/{tool_name}-{desc}/
        Permissions are set to 0o777 for broad accessibility.
    """
    # Create directory structure based on scan ID and tool name
    cwd = os.getcwd()
    dir_path = cwd + os.path.sep + scan_id + \
        os.path.sep + "%s-%s" % (tool_name, desc)

    if not os.path.isdir(dir_path):
        os.makedirs(dir_path)
        os.chmod(dir_path, 0o777)

    return dir_path


def parse_json_blob_file(output_file: str) -> List[Dict[str, Any]]:
    """
    Parse multiple JSON objects from a single file.

    This function reads a file containing multiple JSON objects (one per line
    or concatenated) and returns them as a list. It handles JSON parsing
    errors gracefully and supports files with mixed whitespace.

    Args:
        output_file (str): Path to the file containing JSON objects.

    Returns:
        List[Dict[str, Any]]: List of parsed JSON objects.

    Example:
        >>> objects = parse_json_blob_file('tool_output.json')
        >>> for obj in objects:
        ...     print(obj['hostname'])

    Note:
        This function is commonly used for parsing tool outputs that contain
        multiple JSON objects, such as from nmap, nuclei, or other scanners
        that output one JSON object per discovered item.
    """
    obj_arr = []

    if os.path.exists(output_file):
        # Read all data from file
        with open(output_file, 'r') as file_fd:
            data = file_fd.read()

        if len(data) > 0:
            decoder = JSONDecoder()
            pos = 0

            # Parse multiple JSON objects from the data
            while True:
                # Find next non-whitespace character
                match = NOT_WHITESPACE.search(data, pos)
                if not match:
                    break
                pos = match.start()

                try:
                    obj, pos = decoder.raw_decode(data, pos)
                except JSONDecodeError:
                    logging.getLogger(__name__).error("JSON decoding error")
                    break

                # Add parsed object to results
                obj_arr.append(obj)

    return obj_arr


# Global thread executor instance for framework-wide use
executor = ThreadExecutorWrapper()


def dns_wrapper(domain_set: Set[str]) -> List[Dict[str, str]]:
    """
    Perform DNS resolution for a set of domain names.

    This function takes a set of domain names and performs concurrent DNS resolution
    to obtain their IP addresses. It filters out auto-generated DNS names and
    invalid responses.

    Args:
        domain_set (Set[str]): Set of domain names to resolve

    Returns:
        List[Dict[str, str]]: List of dictionaries containing 'domain' and 'ip' keys
                             for successfully resolved domains

    Example:
        >>> domains = {"example.com", "test.example.com", "api.example.com"}
        >>> results = dns_wrapper(domains)
        >>> for result in results:
        ...     print(f"Domain: {result['domain']} -> IP: {result['ip']}")

    Note:
        - Uses concurrent futures for parallel DNS resolution
        - Filters out domains with auto-generated DNS patterns
        - Ignores resolution failures and invalid responses
        - Filters domains containing IP octets in their names
    """

    ret_list = []
    futures_map = {}

    for domain in domain_set:
        futures_map[domain] = executor.submit(
            socket.gethostbyname, domain)

    # Loop through thread function calls and update progress
    for domain_str in futures_map:

        ip_domain_map = {}

        # Add domain
        ip_domain_map['domain'] = domain_str
        thread_obj = futures_map[domain_str]

        try:
            ip_str = thread_obj.result()
            if ip_str and len(ip_str) > 0:

                # Ignore any autogenerated DNS names
                ip_arr = ip_str.split(".")
                ip_dot = ip_arr[2]+"."+ip_arr[3]
                ip_dash = ip_arr[2]+"-"+ip_arr[3]
                if ip_dot in domain_str or ip_dash in domain_str:
                    continue

                ip_domain_map['ip'] = ip_str

                # Add to the list
                ret_list.append(ip_domain_map)
                # logging.getLogger(__name__).debug("Adding IP %s for hostname %s" %
                #            (ip_str, domain_str))
        except Exception:
            continue

    return ret_list
