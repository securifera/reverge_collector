"""
CrapSecrets Cryptographic Vulnerability Scanner Module.

This module provides comprehensive cryptographic security analysis using CrapSecrets,
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
    Crapsecrets: Main tool class implementing the cryptographic scanner interface
    CrapSecretsScan: Luigi task for executing CrapSecrets vulnerability scanning
    ImportCrapSecretsOutput: Luigi task for importing and processing scan results

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
        crapsecrets = Crapsecrets()
        
        # Execute vulnerability scanning
        success = crapsecrets.scan_func(scan_input_obj)
        
        # Import results
        imported = crapsecrets.import_func(scan_input_obj)

Note:
    This module performs active HTTP requests to analyze cryptographic implementations.
    It should be used responsibly with proper authorization on target systems.
    The tool can identify various types of weak secrets including JWT keys,
    API tokens, and framework-specific cryptographic vulnerabilities.

"""

import json
import os
import luigi
# import traceback
import time
import logging
from typing import Dict, Set, List, Any, Optional, Union

from luigi.util import inherits
from waluigi import scan_utils
from waluigi import data_model
from waluigi.proc_utils import process_wrapper

# Global URL tracking set to prevent duplicate scanning
url_set: Set[str] = set()

# Global path hash mapping for deduplication across vulnerability scans
path_hash_map: Dict[str, Any] = {}


class Crapsecrets(data_model.WaluigiTool):
    """
    CrapSecrets cryptographic vulnerability scanner integration for the Waluigi framework.

    This class provides integration with CrapSecrets, a pure Python library designed
    to identify the use of known or very weak cryptographic secrets across various
    web application platforms. It implements the WaluigiTool interface to provide
    comprehensive cryptographic security analysis within the reconnaissance workflow.

    CrapSecrets specializes in detecting:
        - Weak or default JWT signing keys
        - Known API tokens and secrets
        - Framework-specific cryptographic vulnerabilities
        - Default encryption keys in web applications
        - Predictable or hardcoded cryptographic material
        - Common cryptographic implementation flaws

    Attributes:
        name (str): The tool identifier ('crapsecrets')
        description (str): Human-readable description of the tool's capabilities
        project_url (str): URL to the official CrapSecrets project repository
        collector_type (int): Identifies this as an active scanning tool
        scan_order (int): Execution priority within the scanning workflow (10)
        args (str): Command-line arguments (empty for this tool)
        scan_func (callable): Static method for executing vulnerability scanning
        import_func (callable): Static method for importing scan results

    Methods:
        crapsecrets_scan_func: Executes cryptographic vulnerability scanning operations
        crapsecrets_import: Imports and processes vulnerability scan results

    Example:
        >>> tool = Crapsecrets()
        >>> print(tool.name)
        crapsecrets

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
        Initialize the CrapSecrets tool with default configuration.

        Sets up the tool with appropriate parameters for cryptographic vulnerability
        scanning, including integration points for the scanning and import
        workflow phases.
        """
        super().__init__()
        self.name = 'crapsecrets'
        self.collector_type = data_model.CollectorType.ACTIVE.value
        self.scan_order = 10
        self.args = "-nh -t 3 -mrd 5 -avsk -fvsp"  # No hashcat
        self.description = 'A pure python library for identifying the use of known or very weak cryptographic secrets across a variety of web application platforms.'
        self.project_url = "https://github.com/irsdl/crapsecrets"
        self.input_records = [data_model.ServerRecordType.PORT,
                              data_model.ServerRecordType.HTTP_ENDPOINT_DATA]
        self.output_records = [data_model.ServerRecordType.VULNERABILITY]
        self.scan_func = Crapsecrets.crapsecrets_scan_func
        self.import_func = Crapsecrets.crapsecrets_import

    @staticmethod
    def crapsecrets_scan_func(scan_input: Any) -> bool:
        """
        Execute CrapSecrets cryptographic vulnerability scanning operations.

        This static method serves as the entry point for executing cryptographic
        vulnerability scanning within the Waluigi framework. It builds and runs
        the CrapSecretsScan Luigi task with the provided scan input configuration.

        Args:
            scan_input (Any): The scan input object containing target information,
                            endpoint data, and execution parameters

        Returns:
            bool: True if the vulnerability scanning completed successfully, False otherwise

        Example:
            >>> scan_obj = create_scan_input(...)  # Configure scan
            >>> success = Crapsecrets.crapsecrets_scan_func(scan_obj)
            >>> print(f"Cryptographic vulnerability scan successful: {success}")

        Note:
            Uses Luigi's local scheduler for task execution and provides detailed
            summary information for debugging and monitoring purposes.
        """
        luigi_run_result = luigi.build([CrapSecretsScan(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True

    @staticmethod
    def crapsecrets_import(scan_input: Any) -> bool:
        """
        Import and process CrapSecrets vulnerability scan results.

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
            >>> imported = Crapsecrets.crapsecrets_import(scan_obj)
            >>> print(f"Vulnerability import successful: {imported}")

        Note:
            This method depends on the successful completion of the vulnerability
            scanning phase and processes all discovered cryptographic vulnerabilities
            with detailed categorization and severity assessment.
        """
        luigi_run_result = luigi.build([ImportCrapSecretsOutput(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


def queue_scan(url_dict: Dict[str, Any]) -> Optional[Any]:
    """
    Queue a cryptographic vulnerability scan target with deduplication.

    This function manages the queuing of URLs for CrapSecrets vulnerability scanning
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
        ...     'url': 'https://example.com/api'
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

    This function executes the crapsecrets binary to analyze a target URL for
    cryptographic vulnerabilities. It handles network errors, retries, and
    comprehensive vulnerability detection across various web application platforms.

    Args:
        url_obj (Dict[str, Any]): Dictionary containing URL and metadata including:
                                 - 'url': Target URL for analysis
                                 - 'port_id': Database port identifier
                                 - 'http_endpoint_id': Database endpoint identifier

    Returns:
        Dict[str, Any]: Updated URL object with 'output' field containing
                       CrapSecrets analysis results or empty string if no
                       vulnerabilities found

    Side Effects:
        - Executes crapsecrets binary for each URL
        - Logs debug and error information
        - May retry requests up to 3 times on failure

    Raises:
        Exception: Various exceptions from process execution are caught and logged

    Example:
        >>> url_data = {'url': 'https://example.com/api', 'port_id': 123}
        >>> result = request_wrapper(url_data)
        >>> if result['output']:
        ...     print(f"Vulnerabilities found: {len(result['output'])}")

    Note:
        The function uses the crapsecrets CLI tool via process_wrapper for analysis.
        Results are parsed from the command output.
    """

    url = url_obj['url']
    output = []
    custom_args = url_obj.get('custom_args')

    logging.getLogger(__name__).debug("Scanning URL: %s" % url)

    count = 0
    while True:
        try:

            user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"

            # Build command to run crapsecrets binary
            command = [
                "crapsecrets",
                "--url",
                url,
                "-a",
                user_agent,
                "-j"  # JSON output
            ]

            # Add custom args if provided
            if custom_args:
                command.extend(custom_args)
            ret_dict = process_wrapper(cmd_args=command, store_output=True)

            if ret_dict and 'exit_code' in ret_dict:
                exit_code = ret_dict['exit_code']
                if exit_code == 0:
                    # Parse stdout for results
                    if 'stdout' in ret_dict and ret_dict['stdout']:
                        stdout_text = ret_dict['stdout']
                        try:
                            # Try to parse as JSON if output contains findings
                            if stdout_text.strip():
                                output = json.loads(stdout_text)
                        except json.JSONDecodeError:
                            # If not JSON, store raw output
                            output = [{'raw_output': stdout_text}]
                    elif 'stderr' in ret_dict and ret_dict['stderr']:
                        stderr_text = ret_dict['stderr']
                        logging.getLogger(__name__).error(
                            "Crapsecrets error for URL %s: %s" % (url, stderr_text))

                break
        except Exception as e:
            logging.getLogger(__name__).error(
                "Error scanning URL %s: %s" % (url, str(e)))
            count += 1
            time.sleep(1)
            if count > 2:
                break

    url_obj['output'] = output
    return url_obj


class CrapSecretsScan(luigi.Task):
    """
    Luigi task for executing CrapSecrets cryptographic vulnerability scanning operations.

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
        run: Executes the actual CrapSecrets cryptographic vulnerability scanning

    Example:
        >>> scan_obj = ScanInputObject(...)  # Configured scan input
        >>> task = CrapSecretsScan(scan_input=scan_obj)
        >>> luigi.build([task])

    Note:
        This class inherits from luigi.Task and follows Luigi's task execution model.
        The task processes both discovered HTTP endpoints and custom URL lists to
        provide comprehensive cryptographic vulnerability coverage focused on base URLs.
    """

    scan_input = luigi.Parameter()

    def output(self) -> luigi.LocalTarget:
        """
        Define the output file target for CrapSecrets vulnerability scan results.

        Creates a unique output file path based on the scan ID and tool name,
        ensuring that vulnerability scan results are properly organized and
        accessible to downstream tasks in the Luigi workflow.

        Returns:
            luigi.LocalTarget: A Luigi target representing the output file where
                             CrapSecrets vulnerability scan results will be stored

        Side Effects:
            - Initializes the tool output directory structure if it doesn't exist
            - Creates directory paths as needed for organized output storage

        Example:
            >>> task = CrapSecretsScan(scan_input=scan_obj)
            >>> target = task.output()
            >>> print(target.path)
            /path/to/outputs/crapsecrets/scan_123/crapsecrets_outputs_123

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
        scan_outputs_file = f"{dir_path}{os.path.sep}crapsecrets_outputs_{scan_id}.json"
        return luigi.LocalTarget(scan_outputs_file)

    def run(self) -> None:
        """
        Execute the CrapSecrets cryptographic vulnerability scanning operation.

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
            >>> task = CrapSecretsScan(scan_input=scan_obj)
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

        # Clear global URL set and path hash map on each run
        global url_set
        url_set = set()

        global path_hash_map
        path_hash_map.clear()

        # Extract custom args from tool configuration
        custom_args = None
        if scheduled_scan_obj.current_tool.args:
            custom_args = scheduled_scan_obj.current_tool.args.split(" ")

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
                'url': url_str,
                'custom_args': custom_args
            }
            future_inst = queue_scan(url_obj)
            if future_inst:
                futures.append(future_inst)

        # Process custom scope URLs if no endpoint URLs found
        if len(endpoint_port_obj_map) == 0 and len(url_list) > 0:
            for url in url_list:
                url_obj = {'port_id': None,
                           'http_endpoint_id': None, 'url': url,
                           'custom_args': custom_args}
                future_inst = queue_scan(url_obj)
                if future_inst:
                    futures.append(future_inst)

        if len(futures) == 0:
            logging.getLogger(__name__).debug(
                "No targets to scan for CrapSecrets")

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
                "No targets to scan for CrapSecrets")

        results_dict = {'output_list': output_file_list}

        # Write output file
        with open(output_file_path, 'w') as file_fd:
            file_fd.write(json.dumps(results_dict))


@inherits(CrapSecretsScan)
class ImportCrapSecretsOutput(data_model.ImportToolXOutput):
    """
    Luigi task for importing and processing CrapSecrets vulnerability scan results.

    This task handles the post-processing of CrapSecrets vulnerability outputs,
    parsing scan results, extracting vulnerability details, and importing findings
    into the database structure with proper categorization and severity assessment.

    The class inherits from both CrapSecretsScan (via @inherits decorator) and
    ImportToolXOutput, providing access to scan parameters and import functionality.

    Processing includes:
        - Loading vulnerability scan results from JSON output files
        - Parsing SecretFound findings with detailed vulnerability information
        - Creating database objects for vulnerabilities with proper classification
        - Handling both existing endpoints and new target object creation
        - Comprehensive vulnerability detail extraction and storage

    Attributes:
        Inherits all attributes from CrapSecretsScan including scan_input parameter

    Methods:
        requires: Specifies that CrapSecretsScan must complete before import
        run: Processes vulnerability findings and imports results to database

    Example:
        >>> import_task = ImportCrapSecretsOutput(scan_input=scan_obj)
        >>> luigi.build([import_task])  # Runs CrapSecretsScan then ImportCrapSecretsOutput

    Note:
        This task automatically depends on CrapSecretsScan completion and processes
        all vulnerability findings with detailed categorization including vulnerability
        names, descriptions, and affected cryptographic secrets.
    """

    def requires(self) -> CrapSecretsScan:
        """
        Define task dependencies for the import operation.

        Ensures that the CrapSecretsScan task completes successfully before attempting
        to import and process the cryptographic vulnerability scan results.

        Returns:
            CrapSecretsScan: The vulnerability scanning task that must complete before import

        Example:
            >>> task = ImportCrapSecretsOutput(scan_input=scan_obj)
            >>> deps = task.requires()
            >>> print(type(deps).__name__)
            CrapSecretsScan
        """
        # Requires CrapSecretsScan Task to be run prior
        return CrapSecretsScan(scan_input=self.scan_input)

    def run(self) -> None:
        """
        Process and import CrapSecrets cryptographic vulnerability results into the database.

        This method performs comprehensive processing of vulnerability scan findings,
        including vulnerability classification, detail extraction, and database object
        creation. It handles the complete import workflow from JSON parsing to database
        insertion with proper vulnerability categorization.

        The processing workflow includes:
        - Loading vulnerability scan results from JSON output files
        - Parsing findings with cryptographic vulnerability details
        - Extracting vulnerability names, descriptions, and affected secrets
        - Creating database objects for vulnerabilities with proper relationships
        - Handling new target creation for URLs not in existing scope
        - Comprehensive vulnerability detail storage and classification

        Returns:
            None: Results are imported directly into the database via import_results()

        Side Effects:
            - Creates database records for vulnerabilities with detailed information
            - May create new host, port, and endpoint objects for discovered targets
            - Processes all vulnerability findings from the preceding CrapSecretsScan task
            - Updates vulnerability database with cryptographic weakness information

        Raises:
            json.JSONDecodeError: If scan output files contain invalid JSON
            FileNotFoundError: If expected vulnerability output files are missing
            KeyError: If required fields are missing from vulnerability findings
            Exception: Various exceptions related to vulnerability processing or database operations

        Example:
            >>> task = ImportCrapSecretsOutput(scan_input=scan_obj)
            >>> task.run()  # Processes and imports all vulnerability findings

        Note:
            The method processes output from the crapsecrets CLI tool and extracts
            detailed vulnerability information from the structured findings.
            For new URLs not in the existing scope, it creates appropriate database
            objects using the create_port_objs helper function.
        """

        http_output_file = self.input().path
        scheduled_scan_obj = self.scan_input
        tool_instance_id = scheduled_scan_obj.current_tool_instance_id
        tool_id = scheduled_scan_obj.current_tool.id

        with open(http_output_file, 'r') as file_fd:
            data = file_fd.read()

        if len(data) > 0:

            ret_arr = []
            scan_data_dict = json.loads(data)

            # Get data and map
            output_list = scan_data_dict['output_list']
            if len(output_list) > 0:

                # Parse the output
                logging.getLogger(__name__).debug(
                    "Importing CrapSecrets output with %s" % output_list)
                for entry in output_list:

                    output = entry['output']
                    http_endpoint_id = entry['http_endpoint_id']
                    port_id = entry['port_id']
                    # url = entry.get('url', '')

                    # Handle new JSON format with 'target' and 'results' keys
                    if output:
                        # Extract results list from new format
                        findings = output.get('results', []) if isinstance(
                            output, dict) else output

                        if findings and len(findings) > 0:
                            for finding in findings:
                                try:
                                    # Handle findings from crapsecrets CLI output
                                    if isinstance(finding, dict):
                                        # Extract key vulnerability information
                                        secret_type = finding.get(
                                            'secret_type', 'Unknown')

                                        if 'secret' in finding:
                                            # Add vuln
                                            vuln_obj = data_model.Vuln(
                                                parent_id=port_id)
                                            vuln_obj.collection_tool_instance_id = tool_instance_id
                                            vuln_obj.name = secret_type
                                            # vuln_obj.vuln_details = secret_val
                                            vuln_obj.endpoint_id = http_endpoint_id
                                            ret_arr.append(vuln_obj)

                                        # Add vuln details as a collection module output
                                        module_obj = data_model.CollectionModule(
                                            parent_id=tool_id)
                                        module_obj.collection_tool_instance_id = tool_instance_id
                                        module_obj.name = secret_type
                                        ret_arr.append(module_obj)
                                        module_id = module_obj.id

                                        # Add module output for all scan results
                                        module_output_obj = data_model.CollectionModuleOutput(
                                            parent_id=module_id)
                                        module_output_obj.collection_tool_instance_id = tool_instance_id
                                        module_output_obj.output = json.dumps(
                                            finding)
                                        module_output_obj.port_id = port_id
                                        ret_arr.append(module_output_obj)

                                except Exception as e:
                                    logging.getLogger(__name__).error(
                                        "Error processing finding: %s" % str(e))
                                    continue

            # Import, Update, & Save
            scheduled_scan_obj = self.scan_input
            self.import_results(scheduled_scan_obj, ret_arr)
