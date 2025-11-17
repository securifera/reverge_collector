"""
BadSecrets Cryptographic Vulnerability Scanner Module.

This module provides comprehensive cryptographic security analysis using BadSecrets,
a pure Python library for identifying the use of known or very weak cryptographic
secrets across a variety of web application platforms. It integrates with the Waluigi
framework to perform automated detection of common cryptographic vulnerabilities.

The module focuses on scanning base URLs (root paths) only, filtering out URLs with
specific paths to concentrate vulnerability analysis on the primary endpoints where
cryptographic secrets are most commonly exposed.

The module supports:
    - Detection of known weak cryptographic secrets and keys
    - Analysis of various web application platforms and frameworks
    - HTTP endpoint scanning for cryptographic vulnerabilities focused on base URLs
    - Support for both discovered endpoints and custom URL lists
    - Concurrent processing for performance optimization
    - Comprehensive vulnerability reporting with details
    - Integration with the Waluigi vulnerability management system

Classes:
    Badsecrets: Main tool class implementing the cryptographic scanner interface
    BadSecretsScan: Luigi task for executing BadSecrets vulnerability scanning
    ImportBadSecretsOutput: Luigi task for importing and processing scan results

Functions:
    queue_scan: Manages vulnerability scan target queuing with deduplication
    request_wrapper: Core HTTP request and vulnerability analysis function
    create_port_objs: Creates database objects from URL analysis for new targets

Global Variables:
    url_set: Thread-safe set tracking scanned URLs to prevent duplicates
    path_hash_map: Mapping for web path deduplication across scans

Example:
    Basic usage through the Waluigi framework::
    
        # Initialize the tool
        badsecrets = Badsecrets()
        
        # Execute vulnerability scanning
        success = badsecrets.scan_func(scan_input_obj)
        
        # Import results
        imported = badsecrets.import_func(scan_input_obj)

Note:
    This module performs active HTTP requests to analyze cryptographic implementations.
    It should be used responsibly with proper authorization on target systems.
    The tool can identify various types of weak secrets including JWT keys,
    API tokens, and framework-specific cryptographic vulnerabilities.

"""

import binascii
import hashlib
import json
import os
import luigi
import multiprocessing
# import traceback
import requests
import time
import logging
import netaddr
from typing import Dict, Set, List, Any, Optional, Union

from luigi.util import inherits
from waluigi import scan_utils
from waluigi import data_model
from badsecrets.base import carve_all_modules
from urllib.parse import urlparse

# Global URL tracking set to prevent duplicate scanning
url_set: Set[str] = set()

# Global path hash mapping for deduplication across vulnerability scans
path_hash_map: Dict[str, Any] = {}


class Badsecrets(data_model.WaluigiTool):
    """
    BadSecrets cryptographic vulnerability scanner integration for the Waluigi framework.

    This class provides integration with BadSecrets, a pure Python library designed
    to identify the use of known or very weak cryptographic secrets across various
    web application platforms. It implements the WaluigiTool interface to provide
    comprehensive cryptographic security analysis within the reconnaissance workflow.

    BadSecrets specializes in detecting:
        - Weak or default JWT signing keys
        - Known API tokens and secrets
        - Framework-specific cryptographic vulnerabilities
        - Default encryption keys in web applications
        - Predictable or hardcoded cryptographic material
        - Common cryptographic implementation flaws

    Attributes:
        name (str): The tool identifier ('badsecrets')
        description (str): Human-readable description of the tool's capabilities
        project_url (str): URL to the official BadSecrets project repository
        collector_type (int): Identifies this as an active scanning tool
        scan_order (int): Execution priority within the scanning workflow (10)
        args (str): Command-line arguments (empty for this tool)
        scan_func (callable): Static method for executing vulnerability scanning
        import_func (callable): Static method for importing scan results

    Methods:
        badsecrets_scan_func: Executes cryptographic vulnerability scanning operations
        badsecrets_import: Imports and processes vulnerability scan results

    Example:
        >>> tool = Badsecrets()
        >>> print(tool.name)
        badsecrets

        >>> # Execute cryptographic vulnerability scanning through the framework
        >>> success = tool.scan_func(scan_input_obj)
        >>> if success:
        ...     imported = tool.import_func(scan_input_obj)

    Note:
        The scan_order of 10 positions this tool to run after endpoint discovery
        and initial reconnaissance phases. The tool performs active HTTP requests
        to analyze cryptographic implementations and identify vulnerabilities.
    """

    def __init__(self) -> None:
        """
        Initialize the BadSecrets tool with default configuration.

        Sets up the tool with appropriate parameters for cryptographic vulnerability
        scanning, including integration points for the scanning and import
        workflow phases.
        """
        self.name = 'badsecrets'
        self.collector_type = data_model.CollectorType.ACTIVE.value
        self.scan_order = 10
        self.args = ""
        self.description = 'A pure python library for identifying the use of known or very weak cryptographic secrets across a variety of web application platforms.'
        self.project_url = "https://github.com/blacklanternsecurity/badsecrets"
        self.input_records = [data_model.ServerRecordType.PORT,
                              data_model.ServerRecordType.HTTP_ENDPOINT_DATA]
        self.output_records = [data_model.ServerRecordType.VULNERABILITY]
        self.scan_func = Badsecrets.badsecrets_scan_func
        self.import_func = Badsecrets.badsecrets_import

    @staticmethod
    def badsecrets_scan_func(scan_input: Any) -> bool:
        """
        Execute BadSecrets cryptographic vulnerability scanning operations.

        This static method serves as the entry point for executing cryptographic
        vulnerability scanning within the Waluigi framework. It builds and runs
        the BadSecretsScan Luigi task with the provided scan input configuration.

        Args:
            scan_input (Any): The scan input object containing target information,
                            endpoint data, and execution parameters

        Returns:
            bool: True if the vulnerability scanning completed successfully, False otherwise

        Example:
            >>> scan_obj = create_scan_input(...)  # Configure scan
            >>> success = Badsecrets.badsecrets_scan_func(scan_obj)
            >>> print(f"Cryptographic vulnerability scan successful: {success}")

        Note:
            Uses Luigi's local scheduler for task execution and provides detailed
            summary information for debugging and monitoring purposes.
        """
        luigi_run_result = luigi.build([BadSecretsScan(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True

    @staticmethod
    def badsecrets_import(scan_input: Any) -> bool:
        """
        Import and process BadSecrets vulnerability scan results.

        This static method handles the import phase of the vulnerability scanning
        workflow, processing discovered cryptographic vulnerabilities and importing
        findings into the database structure with proper vulnerability categorization.

        Args:
            scan_input (Any): The scan input object containing configuration
                            and metadata for the import operation

        Returns:
            bool: True if the import completed successfully, False otherwise

        Example:
            >>> # After successful vulnerability scanning
            >>> imported = Badsecrets.badsecrets_import(scan_obj)
            >>> print(f"Vulnerability import successful: {imported}")

        Note:
            This method depends on the successful completion of the vulnerability
            scanning phase and processes all discovered cryptographic vulnerabilities
            with detailed categorization and severity assessment.
        """
        luigi_run_result = luigi.build([ImportBadSecretsOutput(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


def queue_scan(url_dict: Dict[str, Any]) -> Optional[Any]:
    """
    Queue a cryptographic vulnerability scan target with deduplication.

    This function manages the queuing of URLs for BadSecrets vulnerability scanning
    while preventing duplicate scans. It maintains a global set of processed URLs
    to ensure efficient resource utilization and avoid redundant analysis.

    Args:
        url_dict (Dict[str, Any]): Dictionary containing target URL and metadata
                                  including 'url', 'port_id', and 'http_endpoint_id'

    Returns:
        Optional[Any]: Future object for the queued scan task, or None if URL
                      was already queued (duplicate)

    Side Effects:
        - Modifies the global url_set to track processed URLs
        - Submits vulnerability scanning tasks to the executor pool

    Example:
        >>> url_data = {
        ...     'url': 'https://example.com/api',
        ...     'port_id': 123,
        ...     'http_endpoint_id': 456
        ... }
        >>> future = queue_scan(url_data)
        >>> if future:
        ...     result = future.result()

    Note:
        The function prevents duplicate scanning by checking the global url_set.
        Only unique URLs are submitted for vulnerability analysis to optimize
        performance and avoid redundant cryptographic testing.
    """

    global url_set

    url = url_dict['url']
    if url not in url_set:
        url_set.add(url)
        return scan_utils.executor.submit(request_wrapper, url_dict)


def request_wrapper(url_obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    Core HTTP request and cryptographic vulnerability analysis function.

    This function performs the actual HTTP request to the target URL and executes
    BadSecrets analysis to identify cryptographic vulnerabilities. It handles
    network errors, retries, and comprehensive vulnerability detection across
    various web application platforms.

    Args:
        url_obj (Dict[str, Any]): Dictionary containing URL and metadata including:
                                 - 'url': Target URL for analysis
                                 - 'port_id': Database port identifier
                                 - 'http_endpoint_id': Database endpoint identifier

    Returns:
        Dict[str, Any]: Updated URL object with 'output' field containing
                       BadSecrets analysis results or empty string if no
                       vulnerabilities found

    Side Effects:
        - Performs HTTP GET requests to target URLs
        - Logs debug and error information
        - May retry requests up to 3 times on failure

    Raises:
        Exception: Various network and analysis exceptions are caught and logged

    Example:
        >>> url_data = {'url': 'https://example.com/api', 'port_id': 123}
        >>> result = request_wrapper(url_data)
        >>> if result['output']:
        ...     print(f"Vulnerabilities found: {len(result['output'])}")

    Note:
        The function uses a Windows-like User-Agent for consistency and disables
        SSL verification to handle self-signed certificates. Analysis is only
        performed on successful HTTP 200 responses to ensure accurate results.
    """

    url = url_obj['url']
    output = ''

    logging.getLogger(__name__).debug("Scanning URL: %s" % url)
    multiprocessing.log_to_stderr()
    headers = {
        'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"}
    count = 0
    while True:
        try:
            resp = requests.get(url, headers=headers, verify=False, timeout=3)

            # Check if there are any issues
            if resp.status_code == 200:
                output = carve_all_modules(requests_response=resp, url=url)

            break
        except Exception as e:
            logging.getLogger(__name__).error(
                "Error scanning URL %s: %s" % (url, str(e)))
            count += 1
            time.sleep(1)
            if count > 2:
                break

    # if output:
    #    logging.getLogger(__name__).debug("Output for URL %s: %s" % (url, output))

    url_obj['output'] = output
    return url_obj


class BadSecretsScan(luigi.Task):
    """
    Luigi task for executing BadSecrets cryptographic vulnerability scanning operations.

    This task orchestrates the execution of cryptographic vulnerability analysis against
    discovered web endpoints and URLs, managing input parameters, output file generation,
    and execution flow within the Luigi workflow framework. It processes HTTP endpoints
    from previous scanning phases and custom URL lists to identify cryptographic weaknesses.

    The scan focuses on base URLs (root paths) only, filtering out URLs with specific
    paths to concentrate cryptographic vulnerability analysis on the primary endpoints
    where secrets are most commonly exposed.

    Attributes:
        scan_input (luigi.Parameter): The scan input object containing target information,
                                    endpoint data, and configuration parameters

    Methods:
        output: Defines the output file target for the vulnerability scan results
        requires: Specifies task dependencies (inherited from parent tasks)
        run: Executes the actual BadSecrets cryptographic vulnerability scanning

    Example:
        >>> scan_obj = ScanInputObject(...)  # Configured scan input
        >>> task = BadSecretsScan(scan_input=scan_obj)
        >>> luigi.build([task])

    Note:
        This class inherits from luigi.Task and follows Luigi's task execution model.
        The task processes both discovered HTTP endpoints and custom URL lists to
        provide comprehensive cryptographic vulnerability coverage focused on base URLs.
    """

    scan_input = luigi.Parameter()

    def output(self) -> luigi.LocalTarget:
        """
        Define the output file target for BadSecrets vulnerability scan results.

        Creates a unique output file path based on the scan ID and tool name,
        ensuring that vulnerability scan results are properly organized and
        accessible to downstream tasks in the Luigi workflow.

        Returns:
            luigi.LocalTarget: A Luigi target representing the output file where
                             BadSecrets vulnerability scan results will be stored

        Side Effects:
            - Initializes the tool output directory structure if it doesn't exist
            - Creates directory paths as needed for organized output storage

        Example:
            >>> task = BadSecretsScan(scan_input=scan_obj)
            >>> target = task.output()
            >>> print(target.path)
            /path/to/outputs/badsecrets/scan_123/badsecrets_outputs_123

        Note:
            The output file contains JSON data with vulnerability findings,
            including cryptographic weakness details and affected endpoints.
        """

        scheduled_scan_obj = self.scan_input
        scan_id = scheduled_scan_obj.id

        # Init directory
        tool_name = scheduled_scan_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)

        # path to input file
        scan_outputs_file = f"{dir_path}{os.path.sep}badsecrets_outputs_{scan_id}.json"
        return luigi.LocalTarget(scan_outputs_file)

    def run(self) -> None:
        """
        Execute the BadSecrets cryptographic vulnerability scanning operation.

        This method orchestrates the complete vulnerability scanning workflow including:
        - Processing discovered HTTP endpoints using scan_data.get_urls()
        - Filtering to only scan base URLs (root paths) for focused analysis
        - Handling custom URL lists for additional target coverage
        - Concurrent execution of cryptographic vulnerability analysis
        - Collection and aggregation of vulnerability findings

        The method uses the same URL extraction pattern as NucleiScan and FeroxScan,
        filtering URLs to only include base URLs (path is None or "/") to focus
        cryptographic analysis on primary endpoints where secrets are typically exposed.

        Returns:
            None: Vulnerability findings are written to the output file

        Side Effects:
            - Modifies the global url_set to track processed URLs
            - Creates vulnerability scan tasks for concurrent execution
            - Generates output file with aggregated vulnerability data
            - Registers tool executors with the scan management system

        Raises:
            OSError: If output directories cannot be created or accessed
            requests.RequestException: If HTTP requests fail repeatedly
            json.JSONEncodeError: If results cannot be serialized to JSON
            Exception: Various exceptions related to network requests or file I/O

        Example:
            >>> task = BadSecretsScan(scan_input=scan_obj)
            >>> task.run()  # Executes all configured vulnerability scans

        Note:
            The method filters to base URLs only and uses concurrent execution for
            performance. It includes comprehensive error handling for network operations
            and fallback to custom scope URLs when no base URLs are available.
        """

        scheduled_scan_obj = self.scan_input

        # Get output file path
        output_file_path = self.output().path
        output_file_list = []

        # Get all the endpoints to scan using the same pattern as NucleiScan and FeroxScan
        # Filter to only base URLs (skip non-default paths)
        all_endpoint_port_obj_map = scheduled_scan_obj.scan_data.get_urls()
        endpoint_port_obj_map = {}

        # Filter URLs to only include base URLs (path is None or "/")
        for url, port_data in all_endpoint_port_obj_map.items():
            # Only include URLs with no specific path or root path
            if port_data.get('path') is None or port_data.get('path') == '/':
                endpoint_port_obj_map[url] = port_data

        # Also get any custom scope URLs
        scope_obj = scheduled_scan_obj.scan_data
        url_list = scope_obj.get_scope_urls()

        futures = []

        # Process the filtered endpoint URLs
        for url_str, url_metadata in endpoint_port_obj_map.items():
            port_id = url_metadata.get('port_id')
            http_endpoint_id = url_metadata.get('http_endpoint_id')

            url_obj = {
                'port_id': port_id,
                'http_endpoint_id': http_endpoint_id,
                'url': url_str
            }
            future_inst = queue_scan(url_obj)
            if future_inst:
                futures.append(future_inst)

        # Process custom scope URLs if no endpoint URLs found
        if len(endpoint_port_obj_map) == 0 and len(url_list) > 0:
            for url in url_list:
                url_obj = {'port_id': None,
                           'http_endpoint_id': None, 'url': url}
                future_inst = queue_scan(url_obj)
                if future_inst:
                    futures.append(future_inst)

        if len(futures) == 0:
            logging.getLogger(__name__).debug(
                "No targets to scan for BadSecrets")

        # If there are any futures, wait for them to complete
        if len(futures) > 0:
            scan_proc_inst = data_model.ToolExecutor(futures)
            scheduled_scan_obj.register_tool_executor(
                scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

            # Wait for the tasks to complete and retrieve results
            for future in futures:
                ret_obj = future.result()
                if ret_obj:
                    output_file_list.append(ret_obj)
        else:
            logging.getLogger(__name__).debug(
                "No targets to scan for BadSecrets")

        results_dict = {'output_list': output_file_list}

        # Write output file
        with open(output_file_path, 'w') as file_fd:
            file_fd.write(json.dumps(results_dict))


def create_port_objs(ret_arr: List[Any], url: str) -> List[Any]:
    """
    Create database objects from URL analysis for new targets.

    This function parses a URL to extract host, port, and path information,
    then creates appropriate database objects for hosts, ports, and HTTP
    endpoints. It handles both IPv4 and IPv6 addresses and manages path
    deduplication through hashing.

    Args:
        ret_arr (List[Any]): List to append created database objects to
        url (str): Target URL to parse and create objects from

    Returns:
        List[Any]: Updated list containing the original objects plus newly
                  created host, port, path, and endpoint objects

    Side Effects:
        - Modifies the global path_hash_map for path deduplication
        - Creates Host, Port, ListItem, and HttpEndpoint database objects
        - Parses URL components including scheme, host, port, and path

    Raises:
        ValueError: If URL cannot be parsed or contains invalid components
        netaddr.AddrFormatError: If host is not a valid IP address

    Example:
        >>> objects = []
        >>> result = create_port_objs(objects, "https://192.168.1.1:8443/api/v1")
        >>> print(f"Created {len(result)} database objects")
        Created 4 database objects

    Note:
        The function assumes the host portion of the URL is an IP address
        and creates appropriate IPv4 or IPv6 host objects. It handles
        default ports (80 for HTTP, 443 for HTTPS) when not explicitly specified.
    """
    global path_hash_map

    if url:

        port_id = None
        u = urlparse(url)
        host = u.netloc
        scheme = u.scheme
        port = None
        domain_str = None
        if ":" in host:
            host_arr = host.split(":")
            domain_str = host_arr[0].lower()
            port = int(host_arr[1])
        else:
            domain_str = host
            port = None

        web_path = u.path or "/"

        # Fix up port
        if scheme == 'http':
            secure = 0
            if port is None:
                port = 80
        elif scheme == 'https':
            secure = 1
            if port is None:
                port = 443

        ip_object = netaddr.IPAddress(domain_str)

        # Create Host object
        host_obj = data_model.Host()
        if ip_object.version == 4:
            host_obj.ipv4_addr = str(ip_object)
        elif ip_object.version == 6:
            host_obj.ipv6_addr = str(ip_object)

        host_id = host_obj.id

        # Add host
        ret_arr.append(host_obj)

        # Create Port object
        port_obj = data_model.Port(
            parent_id=host_id, id=port_id)
        port_obj.proto = 0
        port_obj.port = str(port)
        port_id = port_obj.id
        port_obj.secure = secure

        # Add port
        ret_arr.append(port_obj)

        hashobj = hashlib.sha1
        hashobj.update(web_path.encode())
        path_hash = hashobj.digest()
        hex_str = binascii.hexlify(path_hash).decode()
        web_path_hash = hex_str

        if web_path_hash in path_hash_map:
            path_obj = path_hash_map[web_path_hash]
        else:
            path_obj = data_model.ListItem()
            path_obj.web_path = web_path
            path_obj.web_path_hash = web_path_hash

            # Add to map and the object list
            path_hash_map[web_path_hash] = path_obj
            ret_arr.append(path_obj)

        web_path_id = path_obj.id

        # Add http endpoint
        http_endpoint_obj = data_model.HttpEndpoint(
            parent_id=port_obj.id)
        http_endpoint_obj.web_path_id = web_path_id

        ret_arr.append(port_obj)

    return ret_arr


@inherits(BadSecretsScan)
class ImportBadSecretsOutput(data_model.ImportToolXOutput):
    """
    Luigi task for importing and processing BadSecrets vulnerability scan results.

    This task handles the post-processing of BadSecrets vulnerability outputs,
    parsing scan results, extracting vulnerability details, and importing findings
    into the database structure with proper categorization and severity assessment.

    The class inherits from both BadSecretsScan (via @inherits decorator) and
    ImportToolXOutput, providing access to scan parameters and import functionality.

    Processing includes:
        - Loading vulnerability scan results from JSON output files
        - Parsing SecretFound findings with detailed vulnerability information
        - Creating database objects for vulnerabilities with proper classification
        - Handling both existing endpoints and new target object creation
        - Comprehensive vulnerability detail extraction and storage

    Attributes:
        Inherits all attributes from BadSecretsScan including scan_input parameter

    Methods:
        requires: Specifies that BadSecretsScan must complete before import
        run: Processes vulnerability findings and imports results to database

    Example:
        >>> import_task = ImportBadSecretsOutput(scan_input=scan_obj)
        >>> luigi.build([import_task])  # Runs BadSecretsScan then ImportBadSecretsOutput

    Note:
        This task automatically depends on BadSecretsScan completion and processes
        all vulnerability findings with detailed categorization including vulnerability
        names, descriptions, and affected cryptographic secrets.
    """

    def requires(self) -> BadSecretsScan:
        """
        Define task dependencies for the import operation.

        Ensures that the BadSecretsScan task completes successfully before attempting
        to import and process the cryptographic vulnerability scan results.

        Returns:
            BadSecretsScan: The vulnerability scanning task that must complete before import

        Example:
            >>> task = ImportBadSecretsOutput(scan_input=scan_obj)
            >>> deps = task.requires()
            >>> print(type(deps).__name__)
            BadSecretsScan
        """
        # Requires BadSecretsScan Task to be run prior
        return BadSecretsScan(scan_input=self.scan_input)

    def run(self) -> None:
        """
        Process and import BadSecrets cryptographic vulnerability results into the database.

        This method performs comprehensive processing of vulnerability scan findings,
        including vulnerability classification, detail extraction, and database object
        creation. It handles the complete import workflow from JSON parsing to database
        insertion with proper vulnerability categorization.

        The processing workflow includes:
        - Loading vulnerability scan results from JSON output files
        - Parsing 'SecretFound' findings with cryptographic vulnerability details
        - Extracting vulnerability names, descriptions, and affected secrets
        - Creating database objects for vulnerabilities with proper relationships
        - Handling new target creation for URLs not in existing scope
        - Comprehensive vulnerability detail storage and classification

        Returns:
            None: Results are imported directly into the database via import_results()

        Side Effects:
            - Creates database records for vulnerabilities with detailed information
            - May create new host, port, and endpoint objects for discovered targets
            - Processes all vulnerability findings from the preceding BadSecretsScan task
            - Updates vulnerability database with cryptographic weakness information

        Raises:
            json.JSONDecodeError: If scan output files contain invalid JSON
            FileNotFoundError: If expected vulnerability output files are missing
            KeyError: If required fields are missing from vulnerability findings
            Exception: Various exceptions related to vulnerability processing or database operations

        Example:
            >>> task = ImportBadSecretsOutput(scan_input=scan_obj)
            >>> task.run()  # Processes and imports all vulnerability findings

        Note:
            The method specifically looks for 'SecretFound' type findings and extracts
            detailed vulnerability information including secret values and descriptions.
            For new URLs not in the existing scope, it creates appropriate database
            objects using the create_port_objs helper function.
        """

        http_output_file = self.input().path
        scheduled_scan_obj = self.scan_input
        tool_instance_id = scheduled_scan_obj.current_tool_instance_id

        with open(http_output_file, 'r') as file_fd:
            data = file_fd.read()

        if len(data) > 0:

            ret_arr = []
            scan_data_dict = json.loads(data)

            # Get data and map
            output_list = scan_data_dict['output_list']
            if len(output_list) > 0:

                # Parse the output
                for entry in output_list:

                    output = entry['output']
                    http_endpoint_id = entry['http_endpoint_id']
                    port_id = entry['port_id']

                    if output and len(output) > 0:
                        for finding in output:
                            finding_type = finding['type']
                            if finding_type == 'SecretFound':

                                if 'secret' in finding:
                                    secret_val = finding['secret']

                                    if 'description' in finding:
                                        vuln_desc = finding['description']

                                        if 'Secret' in vuln_desc:
                                            vuln_name = vuln_desc['Secret']

                                            if port_id is None:
                                                ret_arr = create_port_objs(
                                                    ret_arr, entry['url'])

                                            # Add vuln
                                            vuln_obj = data_model.Vuln(
                                                parent_id=port_id)
                                            vuln_obj.collection_tool_instance_id = tool_instance_id
                                            vuln_obj.name = vuln_name
                                            vuln_obj.vuln_details = secret_val
                                            vuln_obj.endpoint_id = http_endpoint_id
                                            ret_arr.append(vuln_obj)

            # Import, Update, & Save
            scheduled_scan_obj = self.scan_input
            self.import_results(scheduled_scan_obj, ret_arr)
