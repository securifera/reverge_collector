"""
Webcap Screenshot Capture Module.

This module provides comprehensive web page screenshot capabilities using Webcap,
a Python library that leverages Chrome/Chromium for automated web page rendering
and high-quality image capture. It integrates with the Waluigi framework to perform
automated screenshot collection of discovered web endpoints with advanced features.

The module supports:
    - High-quality Chrome-based screenshot capture
    - Asynchronous concurrent processing for performance
    - Configurable timeout, thread count, and image quality settings
    - Support for both HTTP and HTTPS targets with custom headers
    - Domain-based and IP-based screenshot collection
    - Advanced error handling and browser restart capabilities
    - Base64 image encoding and hash-based deduplication
    - Integration with HTTP endpoint discovery results

Classes:
    Webcap: Main tool class implementing the Chrome-based screenshot interface
    WebcapScan: Luigi task for executing screenshot capture operations
    ImportWebcapOutput: Luigi task for importing and processing screenshot results

Functions:
    parse_args: Parses command-line arguments for Webcap configuration
    webcap_asyncio: Asynchronous screenshot capture using Chrome browser
    webcap_wrapper: Synchronous wrapper for async screenshot operations
    queue_scan: Manages screenshot target queuing with deduplication

Global Variables:
    future_map: Thread-safe mapping for tracking queued screenshot targets

Example:
    Basic usage through the Waluigi framework::
    
        # Initialize the tool
        webcap = Webcap()
        
        # Execute screenshot capture
        success = webcap.scan_func(scan_input_obj)
        
        # Import results
        imported = webcap.import_func(scan_input_obj)

Note:
    This module requires Chrome/Chromium to be installed and accessible.
    The tool performs active web requests and should be used responsibly with proper
    authorization on target systems. Webcap provides superior performance and
    quality compared to PhantomJS-based solutions.

.. moduleauthor:: Waluigi Framework Team
.. version:: 1.0.0
"""

import json
import os
import binascii
import luigi
import traceback
import hashlib
import base64
import logging
import asyncio
import shlex
from typing import Dict, Tuple, Any, Optional, List

from luigi.util import inherits
from webcap import Browser
from webcap.errors import WebCapError
from waluigi import scan_utils
from waluigi import data_model

# Global future mapping for screenshot target management and deduplication
future_map: Dict[str, Tuple[int, Optional[int], Optional[str], str]] = {}


class Webcap(data_model.WaluigiTool):
    """
    Webcap Chrome-based screenshot capture integration for the Waluigi framework.

    This class provides integration with Webcap, a modern Python library that uses
    Chrome/Chromium for automated web page screenshot capture. It implements the
    WaluigiTool interface to provide high-quality visual reconnaissance capabilities
    within the security scanning workflow.

    Webcap offers several advantages over PhantomJS-based solutions:
        - Modern Chrome rendering engine for accurate page representation
        - Asynchronous processing for superior performance
        - Configurable quality, timeout, and concurrency settings
        - Better JavaScript execution and modern web standard support
        - Robust error handling with automatic browser restart capabilities

    Attributes:
        name (str): The tool identifier ('webcap')
        description (str): Human-readable description of the tool's capabilities
        project_url (str): URL to the official Webcap project repository
        collector_type (int): Identifies this as an active scanning tool
        scan_order (int): Execution priority within the scanning workflow (8)
        args (str): Default command-line arguments for optimal performance
        scan_func (callable): Static method for executing screenshot operations
        import_func (callable): Static method for importing screenshot results

    Methods:
        webcap_scan_func: Executes Chrome-based screenshot capture operations
        webcap_import: Imports and processes screenshot results

    Example:
        >>> tool = Webcap()
        >>> print(tool.name)
        webcap

        >>> # Execute screenshot capture through the framework
        >>> success = tool.scan_func(scan_input_obj)
        >>> if success:
        ...     imported = tool.import_func(scan_input_obj)

    Note:
        Default arguments include 5-second timeout, 5 concurrent threads, and 100%
        quality for optimal balance of performance and output quality. The scan_order
        of 8 positions this tool to run after endpoint discovery phases.
    """

    def __init__(self) -> None:
        """
        Initialize the Webcap tool with default configuration.

        Sets up the tool with optimized parameters for Chrome-based screenshot
        capture, including performance tuning and logging configuration to
        reduce verbose websocket output.
        """
        self.name = 'webcap'
        self.description = 'A python library that can be used for taking screenshots of web pages using Chrome and Webcap. Currently only the timeout and threads options can be set.'
        self.project_url = 'https://github.com/blacklanternsecurity/webcap'
        self.collector_type = data_model.CollectorType.ACTIVE.value
        self.scan_order = 8
        self.args = "--timeout 5 --threads 5 --quality 20 --format jpeg"
        self.scan_func = Webcap.webcap_scan_func
        self.import_func = Webcap.webcap_import

        # Set logging higher for websockets and httpcore to avoid too much output
        logging.getLogger("websockets.client").setLevel(logging.WARNING)
        logging.getLogger("httpcore.http11").setLevel(logging.WARNING)
        logging.getLogger("httpcore.connection").setLevel(logging.WARNING)

    @staticmethod
    def webcap_scan_func(scan_input: Any) -> bool:
        """
        Execute Webcap Chrome-based screenshot capture operations.

        This static method serves as the entry point for executing Chrome-based
        screenshot capture operations within the Waluigi framework. It builds and
        runs the WebcapScan Luigi task with the provided scan input configuration.

        Args:
            scan_input (Any): The scan input object containing target information,
                            endpoint data, and execution parameters

        Returns:
            bool: True if the screenshot capture completed successfully, False otherwise

        Example:
            >>> scan_obj = create_scan_input(...)  # Configure scan
            >>> success = Webcap.webcap_scan_func(scan_obj)
            >>> print(f"Chrome screenshot capture successful: {success}")

        Note:
            Uses Luigi's local scheduler for task execution and provides detailed
            summary information for debugging and monitoring purposes.
        """
        luigi_run_result = luigi.build([WebcapScan(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True

    @staticmethod
    def webcap_import(scan_input: Any) -> bool:
        """
        Import and process Webcap screenshot results.

        This static method handles the import phase of the screenshot workflow,
        processing captured screenshots and importing findings into the database
        structure with proper metadata, titles, and relationships.

        Args:
            scan_input (Any): The scan input object containing configuration
                            and metadata for the import operation

        Returns:
            bool: True if the import completed successfully, False otherwise

        Example:
            >>> # After successful screenshot capture
            >>> imported = Webcap.webcap_import(scan_obj)
            >>> print(f"Import successful: {imported}")

        Note:
            This method depends on the successful completion of the Chrome-based
            screenshot capture phase and processes all generated screenshot files
            and metadata including page titles and status codes.
        """
        luigi_run_result = luigi.build([ImportWebcapOutput(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


def parse_args(args_str: str) -> Tuple[int, int, int]:
    """
    Parse command-line arguments for Webcap configuration.

    This function extracts timeout, thread count, and quality settings from
    a command-line argument string, providing defaults for any missing values.
    It uses shell-like parsing to handle quoted arguments properly.

    Args:
        args_str (str): Command-line argument string containing Webcap parameters.
                       Expected format: "--timeout 5 --threads 5 --quality 100"

    Returns:
        Tuple[int, int, int]: A tuple containing (timeout, threads, quality)
                             where timeout is in seconds, threads is the concurrent
                             browser count, and quality is image quality percentage

    Example:
        >>> timeout, threads, quality = parse_args("--timeout 10 --threads 3 --quality 90")
        >>> print(f"Config: {timeout}s timeout, {threads} threads, {quality}% quality")
        Config: 10s timeout, 3 threads, 90% quality

        >>> # With defaults for missing values
        >>> timeout, threads, quality = parse_args("--timeout 15")
        >>> print(f"Config: {timeout}s timeout, {threads} threads, {quality}% quality")
        Config: 15s timeout, 5 threads, 100% quality

    Note:
        Default values are: timeout=5, threads=5, quality=100
        Invalid numeric values are silently ignored and defaults are used.
        Uses shlex.split() for proper shell-like argument parsing.
    """
    timeout = 5
    threads = 5
    quality = 100
    image_format = "jpeg"
    if args_str and len(args_str) > 0:
        tokens = shlex.split(args_str)
        for i, token in enumerate(tokens):
            if token == "--timeout" and i + 1 < len(tokens):
                try:
                    timeout = int(tokens[i + 1])
                except ValueError:
                    pass
            if token == "--threads" and i + 1 < len(tokens):
                try:
                    threads = int(tokens[i + 1])
                except ValueError:
                    pass
            if token == "--quality" and i + 1 < len(tokens):
                try:
                    quality = int(tokens[i + 1])
                    # Ensure quality is between 1 and 100
                    quality = max(1, min(quality, 100))
                except ValueError:
                    pass
            if token == "--format" and i + 1 < len(tokens):
                tmp_format = tokens[i + 1]
                # Ensure image format is one of the supported types jpeg, png, webp
                if tmp_format in ["jpeg", "png", "webp"]:
                    image_format = tmp_format

    return timeout, threads, image_format, quality


async def webcap_asyncio(future_map: Dict[str, Tuple], meta_file_path: str,
                         webcap_args: str) -> None:
    """
    Asynchronous Chrome-based screenshot capture operation.

    This async function manages the complete Chrome browser lifecycle and screenshot
    capture process. It handles browser initialization, concurrent screenshot capture,
    error recovery with browser restart, and metadata file generation.

    Args:
        future_map (Dict[str, Tuple]): Mapping of URLs to screenshot target metadata
                                      containing port_id, endpoint_id, domain, and path
        meta_file_path (str): File path where screenshot metadata will be written
        webcap_args (str): Command-line arguments for Webcap configuration

    Returns:
        None: Screenshots and metadata are written to files during execution

    Side Effects:
        - Creates and manages Chrome browser instances
        - Captures screenshots and saves metadata to JSON line format
        - Handles browser restarts on WebCapError exceptions
        - Logs errors and warnings for failed screenshot attempts

    Raises:
        WebCapError: Handled internally with browser restart
        Exception: Various exceptions related to screenshot capture or file I/O

    Example:
        >>> target_map = {"https://example.com": (123, 456, "example.com", "/")}
        >>> await webcap_asyncio(target_map, "/tmp/screenshots.json", "--timeout 10")

    Note:
        The function implements automatic browser restart on WebCapError to handle
        Chrome crashes or unresponsive states. Each screenshot includes URL, image
        data (Base64), status code, title, and associated metadata.
    """

    # Get the arguments for timeout and threads
    timeout, threads, image_format, quality = parse_args(webcap_args)

    # create a browser instance
    browser = Browser(timeout=timeout, threads=threads,
                      image_format=image_format, quality=quality)
    # start the browser
    await browser.start()

    try:
        with open(meta_file_path, 'w') as f:
            for url, scan_tuple in future_map.items():
                port_id, http_endpoint_data_id, domain_str, path = scan_tuple
                url_entry = {'port_id': port_id,
                             'http_endpoint_data_id': http_endpoint_data_id, 'path': path, 'domain': domain_str}

                # take a screenshot
                webscreenshot = None
                try:
                    webscreenshot = await browser.screenshot(url)
                except WebCapError as e:
                    # stop the browser
                    await browser.stop()
                    logging.getLogger(__name__).error(
                        f"WebCapError, restarting browser: {str(e)}")
                    # Restart the browser
                    browser = Browser(timeout=timeout, threads=threads)
                    await browser.start()
                    continue
                except Exception as e:
                    logging.getLogger(__name__).error(
                        f"Error taking screenshot for {url}: {str(e)}")
                    logging.getLogger(__name__).debug(traceback.format_exc())
                    break

                if webscreenshot and webscreenshot.status_code != 0:
                    url_entry['url'] = url
                    try:
                        url_entry['image_data'] = base64.b64encode(
                            webscreenshot.blob).decode()
                    except ValueError as e:
                        # Skip if there is no image data
                        continue
                    url_entry['status_code'] = webscreenshot.status_code
                    url_entry['title'] = webscreenshot.title

                    # Write as JSON line
                    f.write(json.dumps(url_entry) + '\n')
                else:
                    logging.getLogger(__name__).warning(
                        f"Failed to take screenshot for {url}")

                # Force cleanup after each screenshot to manage resources
                await browser.force_cleanup()

    finally:
        # stop the browser
        await browser.stop()


def webcap_wrapper(future_map: Dict[str, Tuple], meta_file_path: str,
                   webcap_scan_args: str) -> Any:
    """
    Synchronous wrapper for asynchronous Webcap screenshot operations.

    This function provides a synchronous interface to the asynchronous Webcap
    screenshot capture functionality, enabling integration with synchronous
    workflow systems while maintaining the performance benefits of async operations.

    Args:
        future_map (Dict[str, Tuple]): Mapping of URLs to screenshot target metadata
        meta_file_path (str): File path where screenshot metadata will be written
        webcap_scan_args (str): Command-line arguments for Webcap configuration

    Returns:
        Any: The result of the async operation (typically None)

    Example:
        >>> target_map = {"https://example.com": (123, 456, "example.com", "/")}
        >>> result = webcap_wrapper(target_map, "/tmp/screenshots.json", "--timeout 10")

    Note:
        Uses asyncio.run() to execute the async screenshot capture in a new
        event loop. This allows the function to be called from synchronous
        code while maintaining async performance benefits.
    """

    return asyncio.run(webcap_asyncio(future_map, meta_file_path, webcap_scan_args))


def queue_scan(host: str, port_str: str, secure: bool, port_id: int,
               query_arg: str = "", domain_str: Optional[str] = None,
               http_endpoint_data_id: Optional[int] = None) -> None:
    """
    Queue a screenshot capture target with deduplication and priority management.

    This function manages the queuing of screenshot targets while preventing
    duplicates and handling priority-based updates. It maintains a global mapping
    of URLs to their associated screenshot tasks and metadata for efficient
    processing.

    Args:
        host (str): The target host (IP address or hostname)
        port_str (str): The target port number as a string
        secure (bool): Whether to use HTTPS (True) or HTTP (False)
        port_id (int): Database identifier for the target port
        query_arg (str, optional): URL path/query string to append. Defaults to "".
        domain_str (str, optional): Domain name for the target. Defaults to None.
        http_endpoint_data_id (int, optional): Database ID for endpoint data. Defaults to None.

    Returns:
        None: This function modifies the global future_map dictionary in-place

    Side Effects:
        - Modifies the global future_map to track queued screenshot targets
        - Implements priority-based replacement for existing targets
        - Constructs URLs for deduplication purposes

    Example:
        >>> queue_scan("192.168.1.1", "443", True, 123,
        ...           query_arg="/admin", domain_str="example.com")
        >>> # Target is now queued for Chrome screenshot capture

    Note:
        If a URL is already queued and the new request has an endpoint data ID
        while the existing one doesn't, the new request takes priority.
        This ensures more specific endpoint data is preserved for better metadata.
    """

    global future_map

    target_str = host
    if domain_str:
        target_str = domain_str

    url = scan_utils.construct_url(target_str, port_str, secure, query_arg)
    if url in future_map:
        scan_tuple = future_map[url]
        port_id, prev_http_endpoint_data_id, domain_str, path = scan_tuple
        # the previous http endoint is None then switch it out to avoid duplicates
        if http_endpoint_data_id is not None and prev_http_endpoint_data_id is None:
            scan_tuple = (port_id, http_endpoint_data_id,
                          domain_str, query_arg)
            future_map[url] = scan_tuple
            return

    else:
        scan_tuple = (port_id, http_endpoint_data_id, domain_str, query_arg)
        future_map[url] = scan_tuple

    return


class WebcapScan(luigi.Task):
    """
    Luigi task for executing Webcap Chrome-based screenshot capture operations.

    This task orchestrates the execution of Chrome-based screenshot capture against
    discovered web endpoints, managing input parameters, output file generation, and
    execution flow within the Luigi workflow framework. It processes HTTP endpoints
    from previous scanning phases and generates high-quality visual documentation.

    Attributes:
        scan_input (luigi.Parameter): The scan input object containing target information,
                                    endpoint data, and configuration parameters

    Methods:
        output: Defines the output file target for the screenshot metadata
        requires: Specifies task dependencies (inherited from parent tasks)
        run: Executes the actual Chrome-based screenshot capture operations

    Example:
        >>> scan_obj = ScanInputObject(...)  # Configured scan input
        >>> task = WebcapScan(scan_input=scan_obj)
        >>> luigi.build([task])

    Note:
        This class inherits from luigi.Task and follows Luigi's task execution model.
        The task processes HTTP endpoints discovered by previous scanning phases
        and generates Chrome-rendered screenshots with comprehensive metadata.
    """

    scan_input = luigi.Parameter()

    def output(self) -> luigi.LocalTarget:
        """
        Define the output file target for Chrome screenshot metadata.

        Creates a unique JSON metadata file path based on the scan ID and tool name,
        ensuring that screenshot metadata is properly organized and accessible to
        downstream tasks in the Luigi workflow.

        Returns:
            luigi.LocalTarget: A Luigi target representing the JSON metadata file where
                             Chrome screenshot information will be stored

        Side Effects:
            - Initializes the tool output directory structure if it doesn't exist
            - Creates directory paths as needed for organized output storage

        Example:
            >>> task = WebcapScan(scan_input=scan_obj)
            >>> target = task.output()
            >>> print(target.path)
            /path/to/outputs/webcap/scan_123/screenshots.json

        Note:
            The metadata file contains JSON lines with screenshot information
            including Base64 image data, URLs, titles, status codes, and
            associated endpoint data for comprehensive documentation.
        """

        scheduled_scan_obj = self.scan_input
        scan_id = scheduled_scan_obj.id

        # Init directory
        tool_name = scheduled_scan_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)

        # Meta file when complete
        meta_file = '%s%s%s' % (dir_path, os.path.sep, 'screenshots.json')

        return luigi.LocalTarget(meta_file)

    def run(self) -> None:
        """
        Execute the Webcap Chrome-based screenshot capture operation.

        This method orchestrates the complete Chrome screenshot workflow including:
        - Processing discovered HTTP endpoints and web paths
        - Queuing screenshot targets with intelligent deduplication
        - Handling both IP-based and domain-based targets
        - Chrome browser-based screenshot execution with async processing
        - Intelligent filtering for likely web endpoints
        - Advanced error handling and recovery

        The method processes all HTTP endpoints from previous scan phases,
        constructs appropriate URLs, and executes Chrome-based screenshot capture
        with configurable timeout, thread count, and quality settings.

        Returns:
            None: Screenshots and metadata are written to the output JSON file

        Side Effects:
            - Modifies the global future_map to track screenshot targets
            - Creates Chrome browser instances for screenshot capture
            - Generates JSON metadata file with screenshot information
            - Registers tool executors with the scan management system

        Raises:
            OSError: If output directories cannot be created or accessed
            WebCapError: If Chrome browser fails to start or capture screenshots
            Exception: Various exceptions related to screenshot capture or file I/O

        Example:
            >>> task = WebcapScan(scan_input=scan_obj)
            >>> task.run()  # Executes all configured Chrome screenshot captures

        Note:
            This method includes intelligent filtering to avoid screenshot attempts
            on non-web ports and uses asynchronous Chrome browser execution for
            superior performance compared to synchronous alternatives.
        """

        global future_map
        # Ensure output folder exists
        dir_path = os.path.dirname(self.output().path)

        logging.getLogger(__name__).debug(
            "WebcapScan started. Output directory: %s" % dir_path)

        scheduled_scan_obj = self.scan_input

        scope_obj = scheduled_scan_obj.scan_data
        target_map = scope_obj.host_port_obj_map
        http_endpoint_port_id_map = scope_obj.http_endpoint_port_id_map
        web_path_map = scope_obj.path_map
        domain_map = scope_obj.domain_map
        endpoint_data_endpoint_id_map = scope_obj.endpoint_data_endpoint_id_map

        webcap_scan_args = scheduled_scan_obj.current_tool.args

        future_map = {}
        for target_key in target_map:

            query_arg = "/"
            target_obj_dict = target_map[target_key]
            port_obj = target_obj_dict['port_obj']

            port_id = port_obj.id
            port_str = port_obj.port
            secure = port_obj.secure

            host_obj = target_obj_dict['host_obj']
            host_id = host_obj.id
            ip_addr = host_obj.ipv4_addr

            # Add domain if it is different from the IP
            domain_str_orig = None
            target_arr = target_key.split(":")
            if target_arr[0] != ip_addr:
                domain_str_orig = target_arr[0]

            if port_id in http_endpoint_port_id_map:
                http_endpoint_obj_list = http_endpoint_port_id_map[port_id]
                for http_endpoint_obj in http_endpoint_obj_list:

                    query_arg = "/"
                    domain_str = domain_str_orig
                    http_endpoint_data_id = None
                    host = ip_addr
                    web_path_id = http_endpoint_obj.web_path_id
                    if web_path_id and web_path_id in web_path_map:
                        web_path_obj = web_path_map[web_path_id]
                        query_arg = web_path_obj.web_path

                    if http_endpoint_obj.id in endpoint_data_endpoint_id_map:
                        http_endpoint_data_obj_list = endpoint_data_endpoint_id_map[
                            http_endpoint_obj.id]

                        for http_endpoint_data_obj in http_endpoint_data_obj_list:

                            domain_str = None
                            http_endpoint_data_id = http_endpoint_data_obj.id
                            domain_id = http_endpoint_data_obj.domain_id
                            if domain_id and domain_id in domain_map:
                                domain_obj = domain_map[domain_id]
                                domain_str = domain_obj.name
                                host = domain_str
                            elif host_id in scope_obj.domain_host_id_map:

                                # Take screenshots for any domains associated with the host
                                temp_domain_list = scope_obj.domain_host_id_map[host_id]
                                for domain_obj in temp_domain_list:
                                    domain_name = domain_obj.name
                                    queue_scan(domain_name, port_str, secure, port_id,
                                               query_arg, domain_name, http_endpoint_data_id)

                            queue_scan(host, port_str, secure, port_id,
                                       query_arg, domain_str, http_endpoint_data_id)

                    else:
                        queue_scan(
                            host, port_str, secure, port_id, query_arg, domain_str)

            else:

                # For hosts without HTTP endpoints, let's try to confirm this is likely a web
                # endpoint so we aren't trying to screencap regular ports
                # First we'll check for the http component, next we'll check if it's port 80 or 443
                likely_http = False
                component_port_id_map = scope_obj.component_port_id_map
                if port_id in component_port_id_map:
                    component_obj_list = component_port_id_map[port_id]
                    for component_obj in component_obj_list:
                        component_name = component_obj.name
                        if 'http' in component_name.lower():
                            likely_http = True
                            break

                if port_str in ['80', '443']:
                    likely_http = True

                # Queue if it is likely an HTTP endpoint
                if likely_http:
                    queue_scan(ip_addr, port_str, secure, port_id,
                               query_arg, domain_str_orig)

                    # Add for domains in the scope
                    if host_id in scope_obj.domain_host_id_map:
                        temp_domain_list = scope_obj.domain_host_id_map[host_id]
                        for domain_obj in temp_domain_list:

                            domain_name = domain_obj.name
                            queue_scan(domain_name, port_str, secure,
                                       port_id, query_arg, domain_name)
                else:
                    logging.getLogger(__name__).debug(
                        "Skipping port %s on host %s as it does not appear to be a web endpoint." % (port_str, ip_addr))

        # Submit the scan task
        meta_file = '%s%s%s' % (dir_path, os.path.sep, 'screenshots.json')
        future_inst = scan_utils.executor.submit(
            webcap_wrapper, future_map, meta_file, webcap_scan_args)

        scan_proc_inst = data_model.ToolExecutor([future_inst])
        scheduled_scan_obj.register_tool_executor(
            scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

        # Wait for the tasks to complete and retrieve results
        future_inst.result()


@inherits(WebcapScan)
class ImportWebcapOutput(data_model.ImportToolXOutput):
    """
    Luigi task for importing and processing Webcap Chrome screenshot results.

    This task handles the post-processing of Webcap screenshot outputs, parsing
    JSON metadata files, processing screenshot images with titles and status codes,
    and importing the findings into the database structure with proper relationships
    and comprehensive metadata.

    The class inherits from both WebcapScan (via @inherits decorator) and
    ImportToolXOutput, providing access to scan parameters and import functionality.

    Processing includes:
        - Loading screenshot metadata from JSON line files
        - Hash-based screenshot deduplication using image content
        - Processing page titles and HTTP status codes
        - Creation of database objects for screenshots, domains, and endpoints
        - Batch import of processed data with relationship mapping
        - Real-time scope updates for immediate availability

    Attributes:
        Inherits all attributes from WebcapScan including scan_input parameter

    Methods:
        requires: Specifies that WebcapScan must complete before import
        run: Processes Chrome screenshot files and imports results to database

    Example:
        >>> import_task = ImportWebcapOutput(scan_input=scan_obj)
        >>> luigi.build([import_task])  # Runs WebcapScan then ImportWebcapOutput

    Note:
        This task automatically depends on WebcapScan completion and processes
        all screenshot data and metadata generated during the Chrome capture phase.
        Uses SHA-1 hashing for both screenshot and path deduplication with
        comprehensive title and status code processing.
    """

    def requires(self) -> WebcapScan:
        """
        Define task dependencies for the import operation.

        Ensures that the WebcapScan task completes successfully before attempting
        to import and process the Chrome screenshot results and metadata.

        Returns:
            WebcapScan: The Chrome screenshot capture task that must complete before import

        Example:
            >>> task = ImportWebcapOutput(scan_input=scan_obj)
            >>> deps = task.requires()
            >>> print(type(deps).__name__)
            WebcapScan
        """
        # Requires WebcapScan Task to be run prior
        return WebcapScan(scan_input=self.scan_input)

    def run(self) -> None:
        """
        Process and import Webcap Chrome screenshot results into the database.

        This method performs comprehensive processing of Chrome screenshot files and
        metadata, including image hashing, title extraction, status code processing,
        and database object creation. It handles the complete import workflow from
        JSON line file processing to database insertion with proper relationship mapping.

        The processing workflow includes:
        - Loading screenshot metadata from JSON line files
        - Processing Base64-encoded screenshot images with hash-based deduplication
        - Extracting page titles and HTTP status codes from Chrome capture
        - Creating domain, path, endpoint, and screenshot database objects
        - Real-time batch importing with proper relationship mapping
        - Updating scan scope with imported data for immediate availability
        - Comprehensive logging and error handling

        Returns:
            None: Results are imported directly into the database via batch operations

        Side Effects:
            - Creates database records for screenshots, domains, paths, and endpoints
            - Updates deduplication maps for screenshots and paths
            - Processes all screenshot metadata from the preceding WebcapScan task
            - Writes import results to the tool import file with JSON line format
            - Updates scan scope for real-time data availability

        Raises:
            json.JSONDecodeError: If metadata files contain invalid JSON
            FileNotFoundError: If expected screenshot metadata files are missing
            base64.binascii.Error: If Base64 image data cannot be decoded
            Exception: Various exceptions related to image processing or database operations

        Example:
            >>> task = ImportWebcapOutput(scan_input=scan_obj)
            >>> task.run()  # Processes and imports all Chrome screenshot results

        Note:
            Uses SHA-1 hashing for both screenshot and web path deduplication.
            Screenshot images are processed as Base64-encoded strings from Chrome.
            The method handles both existing and new HTTP endpoint data objects
            with comprehensive title and status code metadata.
        """

        meta_file = self.input().path
        scheduled_scan_obj = self.scan_input
        tool_instance_id = scheduled_scan_obj.current_tool_instance_id
        scan_id = scheduled_scan_obj.scan_id
        recon_manager = scheduled_scan_obj.scan_thread.recon_manager
        tool_obj = scheduled_scan_obj.current_tool
        tool_id = tool_obj.id

        path_hash_map = {}
        screenshot_hash_map = {}
        domain_name_id_map = {}

        if os.path.exists(meta_file):

            tool_import_file = self.output().path
            with open(meta_file, 'r') as file_fd, open(tool_import_file, 'w') as import_fd:
                count = 0
                for line in file_fd:
                    if not line.strip():
                        continue

                    ret_arr = []
                    screenshot_meta = json.loads(line)
                    web_path = screenshot_meta['path']
                    port_id = screenshot_meta['port_id']
                    status_code = screenshot_meta['status_code']
                    screenshot_bytes_b64 = screenshot_meta['image_data']
                    title = screenshot_meta['title']
                    http_endpoint_data_id = screenshot_meta['http_endpoint_data_id']

                    # Hash the image
                    screenshot_id = None
                    hash_alg = hashlib.sha1
                    hashobj = hash_alg()
                    hashobj.update(base64.b64decode(screenshot_bytes_b64))
                    image_hash = hashobj.digest()
                    image_hash_str = binascii.hexlify(image_hash).decode()

                    if image_hash_str in screenshot_hash_map:
                        screenshot_obj = screenshot_hash_map[image_hash_str]
                    else:
                        screenshot_obj = data_model.Screenshot()
                        screenshot_obj.collection_tool_instance_id = tool_instance_id
                        screenshot_obj.screenshot = screenshot_bytes_b64
                        screenshot_obj.image_hash = image_hash_str

                        # Add to map and the object list
                        screenshot_hash_map[image_hash_str] = screenshot_obj

                    ret_arr.append(screenshot_obj)

                    screenshot_id = screenshot_obj.id

                    hashobj = hash_alg()
                    hashobj.update(web_path.encode())
                    path_hash = hashobj.digest()
                    hex_str = binascii.hexlify(path_hash).decode()
                    web_path_hash = hex_str

                    # Domain key exists and is not None
                    endpoint_domain_id = None
                    if 'domain' in screenshot_meta and screenshot_meta['domain']:
                        domain_str = screenshot_meta['domain']
                        if domain_str in domain_name_id_map:
                            domain_obj = domain_name_id_map[domain_str]
                        else:
                            domain_obj = data_model.Domain()
                            domain_obj.collection_tool_instance_id = tool_instance_id
                            domain_obj.name = domain_str
                            domain_name_id_map[domain_str] = domain_obj

                        # Add domain
                        ret_arr.append(domain_obj)
                        # Set endpoint id
                        endpoint_domain_id = domain_obj.id

                    if web_path_hash in path_hash_map:
                        path_obj = path_hash_map[web_path_hash]
                    else:
                        path_obj = data_model.ListItem()
                        path_obj.collection_tool_instance_id = tool_instance_id
                        path_obj.web_path = web_path
                        path_obj.web_path_hash = web_path_hash

                        # Add to map and the object list
                        path_hash_map[web_path_hash] = path_obj

                    # Add path object
                    ret_arr.append(path_obj)

                    web_path_id = path_obj.id

                    # Add http endpoint
                    http_endpoint_obj = data_model.HttpEndpoint(
                        parent_id=port_id)
                    http_endpoint_obj.collection_tool_instance_id = tool_instance_id
                    http_endpoint_obj.web_path_id = web_path_id

                    # Add the endpoint
                    ret_arr.append(http_endpoint_obj)

                    # Add http endpoint data
                    http_endpoint_data_obj = data_model.HttpEndpointData(
                        parent_id=http_endpoint_obj.id)
                    http_endpoint_data_obj.collection_tool_instance_id = tool_instance_id
                    http_endpoint_data_obj.domain_id = endpoint_domain_id
                    http_endpoint_data_obj.status = status_code
                    http_endpoint_data_obj.title = title
                    http_endpoint_data_obj.screenshot_id = screenshot_id

                    # Set the object id if the object already exists
                    if http_endpoint_data_id:
                        http_endpoint_data_obj.id = http_endpoint_data_id

                    # Add the endpoint
                    ret_arr.append(http_endpoint_data_obj)

                    if len(ret_arr) > 0:

                        record_map = {}
                        import_arr = []
                        for obj in ret_arr:
                            record_map[obj.id] = obj
                            flat_obj = obj.to_jsonable()
                            import_arr.append(flat_obj)

                        # Import the ports to the manager
                        updated_record_map = recon_manager.import_data(
                            scan_id, tool_id, import_arr)

                        # Update the records
                        updated_import_arr = data_model.update_scope_array(
                            record_map, updated_record_map)

                        import_fd.write(json.dumps(updated_import_arr) + '\n')

                        # Update the scan scope
                        scheduled_scan_obj.scan_data.update(record_map)

                    count += 1

                logging.getLogger(__name__).debug(
                    "Imported %d screenshots to manager." % (count))

        else:

            logging.getLogger(__name__).error(
                "[-] Screenshot file does not exist.")
