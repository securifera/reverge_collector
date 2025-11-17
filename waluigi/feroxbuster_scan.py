"""
Feroxbuster Web Directory Scanner Module.

This module provides comprehensive web directory scanning capabilities using Feroxbuster,
a fast, simple, and flexible web directory scanner written in Rust. It integrates with
the Waluigi framework to perform automated directory brute-forcing against web targets.

The module supports:
    - High-performance directory scanning with rate limiting
    - JSON output parsing and structured data extraction
    - Multi-target concurrent scanning
    - Domain and IP-based target resolution
    - HTTP endpoint discovery and cataloging
    - Integration with Luigi workflow management

Classes:
    Feroxbuster: Main tool class implementing the scanner interface
    FeroxScan: Luigi task for executing Feroxbuster scans
    ImportFeroxOutput: Luigi task for importing and processing scan results

Functions:
    queue_url: Queues URLs for scanning and manages output file mapping

Global Variables:
    url_set: Thread-safe set tracking queued URLs to prevent duplicates

Example:
    Basic usage through the Waluigi framework::
    
        # Initialize the tool
        ferox = Feroxbuster()
        
        # Execute scan
        success = ferox.scan_func(scan_input_obj)
        
        # Import results
        imported = ferox.import_func(scan_input_obj)

Note:
    This module requires Feroxbuster to be installed and available in the system PATH.
    The tool performs active scanning and should be used responsibly with proper
    authorization on target systems.

"""

from functools import partial
import json
import os
from typing import Dict, Any, Set, Optional, List, Union
import netaddr
import luigi
import traceback
import random
import hashlib
import binascii
import logging

from luigi.util import inherits
from waluigi import scan_utils
from urllib.parse import urlparse
from waluigi import data_model
from waluigi.proc_utils import process_wrapper

# Global URL tracking set to prevent duplicate scanning
url_set: Set[str] = set()


class Feroxbuster(data_model.WaluigiTool):
    """
    Feroxbuster web directory scanner integration for the Waluigi framework.

    This class provides integration with Feroxbuster, a fast, simple, and flexible
    web directory scanner written in Rust. It implements the WaluigiTool interface
    to provide directory brute-forcing capabilities within the reconnaissance workflow.

    Feroxbuster is particularly effective for discovering hidden directories and files
    on web servers through dictionary-based brute-force attacks with high performance
    and reliability.

    Attributes:
        name (str): The tool identifier ('feroxbuster')
        description (str): Human-readable description of the tool's purpose
        project_url (str): URL to the official Feroxbuster project repository
        collector_type (int): Identifies this as an active scanning tool
        scan_order (int): Execution priority within the scanning workflow (10)
        args (str): Default command-line arguments for optimal scanning
        scan_func (callable): Static method for executing scan operations
        import_func (callable): Static method for importing scan results

    Methods:
        feroxbuster_scan_func: Executes directory scanning operations
        feroxbuster_import: Imports and processes scan results

    Example:
        >>> tool = Feroxbuster()
        >>> print(tool.name)
        feroxbuster

        >>> # Execute scan through the framework
        >>> success = tool.scan_func(scan_input_obj)
        >>> if success:
        ...     imported = tool.import_func(scan_input_obj)

    Note:
        Default arguments include rate limiting (50 req/s), filtering for 200 status
        codes, and no recursion to balance performance with target server load.
        The scan_order of 10 positions this tool appropriately in the workflow.
    """

    def __init__(self) -> None:
        """
        Initialize the Feroxbuster tool with default configuration.

        Sets up the tool with optimized default parameters for web directory
        scanning, including rate limiting and response filtering to ensure
        effective and responsible scanning behavior.
        """
        self.name = 'feroxbuster'
        self.description = 'Feroxbuster is a fast, simple, and flexible web directory scanner written in Rust'
        self.project_url = "https://github.com/epi052/feroxbuster"
        self.collector_type = data_model.CollectorType.ACTIVE.value
        self.scan_order = 10
        self.args = "--rate-limit 50 -s 200 -n --auto-bail"
        self.scan_func = Feroxbuster.feroxbuster_scan_func
        self.import_func = Feroxbuster.feroxbuster_import
        self.input_records = [data_model.ServerRecordType.PORT,
                              data_model.ServerRecordType.HTTP_ENDPOINT_DATA]
        self.output_records = [
            data_model.ServerRecordType.DOMAIN,
            data_model.ServerRecordType.LIST_ITEM,
            data_model.ServerRecordType.HTTP_ENDPOINT,
            data_model.ServerRecordType.HTTP_ENDPOINT_DATA
        ]

    @staticmethod
    def feroxbuster_scan_func(scan_input: Any) -> bool:
        """
        Execute Feroxbuster directory scanning operations.

        This static method serves as the entry point for executing Feroxbuster scans
        within the Waluigi framework. It builds and runs the FeroxScan Luigi task
        with the provided scan input configuration.

        Args:
            scan_input (Any): The scan input object containing target information,
                            tool configuration, and execution parameters

        Returns:
            bool: True if the scan completed successfully, False otherwise

        Example:
            >>> scan_obj = create_scan_input(...)  # Configure scan
            >>> success = Feroxbuster.feroxbuster_scan_func(scan_obj)
            >>> print(f"Scan successful: {success}")

        Note:
            Uses Luigi's local scheduler for task execution and provides detailed
            summary information for debugging and monitoring purposes.
        """
        luigi_run_result = luigi.build([FeroxScan(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True

    @staticmethod
    def feroxbuster_import(scan_input: Any) -> bool:
        """
        Import and process Feroxbuster scan results.

        This static method handles the import phase of the scanning workflow,
        processing Feroxbuster output files and importing discovered findings
        into the database structure.

        Args:
            scan_input (Any): The scan input object containing configuration
                            and metadata for the import operation

        Returns:
            bool: True if the import completed successfully, False otherwise

        Example:
            >>> # After successful scan execution
            >>> imported = Feroxbuster.feroxbuster_import(scan_obj)
            >>> print(f"Import successful: {imported}")

        Note:
            This method depends on the successful completion of the scan phase
            and processes all generated output files for database import.
        """
        luigi_run_result = luigi.build([ImportFeroxOutput(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


class FeroxScan(luigi.Task):
    """
    Luigi task for executing Feroxbuster directory scanning operations.

    This task orchestrates the execution of Feroxbuster scans against web targets,
    managing input parameters, output file generation, and execution flow within
    the Luigi workflow framework.

    Attributes:
        scan_input (luigi.Parameter): The scan input object containing target information
                                    and configuration parameters for the scan operation

    Methods:
        output: Defines the output file target for the scan results
        requires: Specifies task dependencies (inherited from parent tasks)
        run: Executes the actual Feroxbuster scanning operation

    Example:
        >>> scan_obj = ScanInputObject(...)  # Configured scan input
        >>> task = FeroxScan(scan_input=scan_obj)
        >>> luigi.build([task])

    Note:
        This class inherits from luigi.Task and follows Luigi's task execution model.
        The scan results are written to a file target that other tasks can depend on.
    """

    scan_input = luigi.Parameter()

    def output(self) -> luigi.LocalTarget:
        """
        Define the output file target for Feroxbuster scan results.

        Creates a unique output file path based on the scan ID and tool name,
        ensuring that scan results are properly organized and accessible to
        downstream tasks in the Luigi workflow.

        Returns:
            luigi.LocalTarget: A Luigi target representing the output file where
                             Feroxbuster scan results will be stored

        Side Effects:
            - Initializes the tool output directory structure if it doesn't exist
            - Creates directory paths as needed for organized output storage

        Example:
            >>> task = FeroxScan(scan_input=scan_obj)
            >>> target = task.output()
            >>> print(target.path)
            /path/to/outputs/feroxbuster/scan_123/ferox_outputs_123

        Note:
            The output file naming convention includes the scan ID to ensure
            uniqueness across multiple scan operations.
        """

        scheduled_scan_obj = self.scan_input
        scan_id = scheduled_scan_obj.id

        # Init directory
        tool_name = scheduled_scan_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)

        scan_outputs_file = dir_path + os.path.sep + "ferox_outputs_" + scan_id
        return luigi.LocalTarget(scan_outputs_file)

    def run(self) -> None:
        """
        Execute the Feroxbuster directory scanning operation.

        This method orchestrates the complete scanning workflow including:
        - Target URL extraction using scan_data.get_urls()
        - Command construction with appropriate arguments
        - Concurrent execution of multiple scan processes
        - Result collection and output file generation

        The method uses the same URL extraction pattern as NucleiScan, leveraging
        the get_urls() method to handle URL construction, domain resolution, and
        path discovery automatically.

        Returns:
            None: Results are written to the output file specified by self.output()

        Side Effects:
            - Modifies the global url_set to track processed URLs
            - Creates output files for each target scan
            - Registers tool executors with the scan management system
            - Writes consolidated results to the main output file

        Raises:
            OSError: If output directories cannot be created or accessed
            subprocess.SubprocessError: If Feroxbuster execution fails
            json.JSONEncodeError: If results cannot be serialized to JSON
            Exception: Various exceptions related to file I/O

        Example:
            >>> task = FeroxScan(scan_input=scan_obj)
            >>> task.run()  # Executes all configured scans

        Note:
            This method uses concurrent execution for performance and follows
            the same URL extraction pattern as other web scanning tools in the
            framework for consistency.
        """

        global url_set
        url_set = set()

        scheduled_scan_obj = self.scan_input

        # Get output file path
        output_file_path = self.output().path
        output_dir = os.path.dirname(output_file_path)

        url_to_id_map = {}
        tool_args = scheduled_scan_obj.current_tool.args
        if tool_args:
            tool_args = tool_args.split(" ")

        scan_wordlist = None
        if scheduled_scan_obj.current_tool.wordlist_path and os.path.exists(scheduled_scan_obj.current_tool.wordlist_path):
            scan_wordlist = scheduled_scan_obj.current_tool.wordlist_path

        # Get all the URLs to scan using the same pattern as NucleiScan
        endpoint_url_map = scheduled_scan_obj.scan_data.get_urls()

        # Convert the endpoint URL map to the format expected by FeroxScan
        # Skip URLs that already have specific paths (not "/") since Feroxbuster discovers paths
        for url_str, url_metadata in endpoint_url_map.items():
            host_id = url_metadata.get('host_id')
            port_id = url_metadata.get('port_id')
            path = url_metadata.get('path')

            # Skip entries that have non-default paths since Feroxbuster is for path discovery
            if path is not None and path != "/":
                continue

            if url_str and url_str not in url_set:
                url_set.add(url_str)
                rand_str = str(random.randint(1000000, 2000000))

                # Add to url_to_id_map
                scan_output_file_path = output_dir + os.path.sep + "ferox_out_" + rand_str
                url_to_id_map[url_str] = {
                    'port_id': port_id,
                    'host_id': host_id,
                    'output_file': scan_output_file_path
                }

        futures = []
        for target_url in url_to_id_map:

            # Get output file
            scan_output_file_path = url_to_id_map[target_url]['output_file']

            command = []
            if os.name != 'nt':
                command.append("sudo")

            command_arr = [
                "feroxbuster",
                "--json",
                "-k",  # Disable cert validation
                # "-q", # Quiet
                "-A",  # Random User Agent
                # "--thorough", # Collects words, extensions, and links in content
                # "--auto-tune", # Resets speed based on errors
                # "--auto-bail",  # Quits after too many errors
                "-u",
                target_url,
                "-o",
                scan_output_file_path
            ]

            command.extend(command_arr)

            # Add optional arguments
            if tool_args and len(tool_args) > 0:
                command.extend(tool_args)

            # Add wordlist if provided
            if scan_wordlist:
                command.extend(['-w', scan_wordlist])

            callback_with_tool_id = partial(
                scheduled_scan_obj.register_tool_executor, scheduled_scan_obj.current_tool_instance_id)

            futures.append(scan_utils.executor.submit(
                process_wrapper, cmd_args=command, pid_callback=callback_with_tool_id))

        # Register futures
        scan_proc_inst = data_model.ToolExecutor(futures)
        scheduled_scan_obj.register_tool_executor(
            scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

        results_dict = {'url_to_id_map': url_to_id_map}

        # Write output file
        with open(output_file_path, 'w') as file_fd:
            file_fd.write(json.dumps(results_dict))

        # Wait for the tasks to complete and retrieve results
        for future in futures:
            ret_dict = future.result()
            if ret_dict and 'exit_code' in ret_dict:
                exit_code = ret_dict['exit_code']
                if exit_code != 0:
                    err_msg = ''
                    if 'stderr' in ret_dict and ret_dict['stderr']:
                        err_msg = ret_dict['stderr']
                    logging.getLogger(__name__).error(
                        "Feroxbuster scan for scan ID %s exited with code %d: %s" % (scheduled_scan_obj.id, exit_code, err_msg))
                    raise RuntimeError("Feroxbuster scan for scan ID %s exited with code %d: %s" % (
                        scheduled_scan_obj.id, exit_code, err_msg))


@inherits(FeroxScan)
class ImportFeroxOutput(data_model.ImportToolXOutput):
    """
    Luigi task for importing and processing Feroxbuster scan results.

    This task handles the post-processing of Feroxbuster scan outputs, parsing
    JSON results, extracting discovered directories and files, and importing
    the findings into the database structure.

    The class inherits from both FeroxScan (via @inherits decorator) and
    ImportToolXOutput, providing access to scan parameters and import functionality.

    Attributes:
        Inherits all attributes from FeroxScan including scan_input parameter

    Methods:
        requires: Specifies that FeroxScan must complete before import
        run: Processes scan output files and imports results to database

    Example:
        >>> import_task = ImportFeroxOutput(scan_input=scan_obj)
        >>> luigi.build([import_task])  # Runs FeroxScan then ImportFeroxOutput

    Note:
        This task automatically depends on FeroxScan completion and processes
        all output files generated during the scanning phase.
    """

    def requires(self) -> FeroxScan:
        """
        Define task dependencies for the import operation.

        Ensures that the FeroxScan task completes successfully before attempting
        to import and process the scan results.

        Returns:
            FeroxScan: The scanning task that must complete before import

        Example:
            >>> task = ImportFeroxOutput(scan_input=scan_obj)
            >>> deps = task.requires()
            >>> print(type(deps).__name__)
            FeroxScan
        """
        # Requires HttpScan Task to be run prior
        return FeroxScan(scan_input=self.scan_input)

    def run(self) -> None:
        """
        Process and import Feroxbuster scan results into the database.

        This method performs comprehensive processing of Feroxbuster JSON output files,
        extracting discovered web paths, HTTP endpoints, and status codes. It creates
        appropriate database objects for domains, paths, and HTTP endpoints while
        avoiding duplicates through hash-based deduplication.

        The processing workflow includes:
        - Loading scan results from JSON output files
        - Parsing Feroxbuster response objects
        - Extracting and hashing web paths for deduplication
        - Creating domain objects for discovered hostnames
        - Generating HTTP endpoint and endpoint data records
        - Importing all findings into the database

        Returns:
            None: Results are imported directly into the database via self.import_results()

        Side Effects:
            - Creates database records for discovered domains, paths, and endpoints
            - Updates path_hash_map and domain_name_id_map for deduplication
            - Processes all output files from the preceding FeroxScan task

        Raises:
            json.JSONDecodeError: If scan output files contain invalid JSON
            FileNotFoundError: If expected output files are missing
            KeyError: If required fields are missing from scan results
            Exception: Various exceptions related to URL parsing or database operations

        Example:
            >>> task = ImportFeroxOutput(scan_input=scan_obj)
            >>> task.run()  # Processes and imports all scan results

        Note:
            Uses SHA-1 hashing for web path deduplication and handles both IP
            addresses and domain names in discovered URLs. The method processes
            only 'response' type entries from Feroxbuster output.
        """

        path_hash_map = {}
        domain_name_id_map = {}

        scheduled_scan_obj = self.scan_input
        tool_instance_id = scheduled_scan_obj.current_tool_instance_id

        http_output_file = self.input().path
        with open(http_output_file, 'r') as file_fd:
            data = file_fd.read()

        ret_arr = []
        hash_alg = hashlib.sha1
        if len(data) > 0:
            scan_data_dict = json.loads(data)

            # Get data and map
            url_to_id_map = scan_data_dict['url_to_id_map']
            for url_str in url_to_id_map:

                obj_data = url_to_id_map[url_str]
                output_file = obj_data['output_file']
                port_id = obj_data['port_id']
                host_id = obj_data['host_id']

                obj_arr = scan_utils.parse_json_blob_file(output_file)
                for web_result in obj_arr:

                    if 'type' in web_result:
                        result_type = web_result['type']

                        # Get the port object that maps to this url
                        if result_type == "response":

                            if 'status' in web_result:
                                status_code = web_result['status']
                                endpoint_url = None

                                if 'url' in web_result:
                                    endpoint_url = web_result['url']

                                    u = urlparse(endpoint_url)
                                    web_path_str = u.path
                                    if web_path_str and len(web_path_str) > 0:
                                        hashobj = hash_alg()
                                        hashobj.update(web_path_str.encode())
                                        path_hash = hashobj.digest()
                                        web_path_hash = binascii.hexlify(
                                            path_hash).decode()

                                    host = u.netloc
                                    if ":" in host:
                                        host_arr = host.split(":")
                                        domain_str = host_arr[0].lower()
                                    else:
                                        domain_str = host.lower()

                                    # Check if the domain is an IP adress
                                    endpoint_domain_id = None
                                    try:
                                        netaddr.IPAddress(domain_str)
                                    except Exception as e:

                                        if domain_str in domain_name_id_map:
                                            endpoint_domain_id = domain_name_id_map[domain_str]
                                        else:
                                            domain_obj = data_model.Domain(
                                                parent_id=host_id)
                                            domain_obj.collection_tool_instance_id = tool_instance_id
                                            domain_obj.name = domain_str

                                            # Add domain
                                            ret_arr.append(domain_obj)
                                            # Set endpoint id
                                            endpoint_domain_id = domain_obj.id
                                            domain_name_id_map[domain_str] = endpoint_domain_id

                                            # Add domain
                                            ret_arr.append(domain_obj)

                                    if web_path_hash in path_hash_map:
                                        path_obj = path_hash_map[web_path_hash]
                                    else:
                                        path_obj = data_model.ListItem()
                                        path_obj.collection_tool_instance_id = tool_instance_id
                                        path_obj.web_path = web_path_str
                                        path_obj.web_path_hash = web_path_hash

                                        # Add to map and the object list
                                        path_hash_map[web_path_hash] = path_obj
                                        ret_arr.append(path_obj)

                                    web_path_id = path_obj.id

                                    # Create http endpoint
                                    http_endpoint_obj = data_model.HttpEndpoint(
                                        parent_id=port_id)
                                    http_endpoint_obj.collection_tool_instance_id = tool_instance_id
                                    http_endpoint_obj.web_path_id = web_path_id

                                    # Add the endpoint
                                    ret_arr.append(http_endpoint_obj)

                                    http_endpoint_data_obj = data_model.HttpEndpointData(
                                        parent_id=http_endpoint_obj.id)
                                    http_endpoint_data_obj.collection_tool_instance_id = tool_instance_id
                                    http_endpoint_data_obj.domain_id = endpoint_domain_id
                                    http_endpoint_data_obj.status = status_code

                                    # Add the endpoint
                                    ret_arr.append(http_endpoint_data_obj)

        scheduled_scan_obj = self.scan_input
        self.import_results(scheduled_scan_obj, ret_arr)
