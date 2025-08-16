"""
Nuclei vulnerability scanning module for the Waluigi framework.

This module provides vulnerability scanning capabilities using Nuclei, a fast and flexible
vulnerability scanner based on YAML templates. It performs automated security scans on
web applications and services to identify potential vulnerabilities and components.

The module focuses on scanning base URLs (root paths) only, filtering out URLs with
specific paths to concentrate vulnerability scanning efforts on the primary endpoints.

The module implements both scanning and data import functionality through Luigi tasks,
supporting modular scanning operations and comprehensive result processing.

Classes:
    Nuclei: Tool configuration class for Nuclei scanner
    NucleiScan: Luigi task for executing Nuclei vulnerability scans
    ImportNucleiOutput: Luigi task for processing and importing Nuclei scan results

"""

from functools import partial
import json
import os
from typing import Dict, Any, List, Set, Optional
import luigi
import logging

from luigi.util import inherits
from waluigi import scan_utils
from waluigi import data_model
from waluigi.proc_utils import process_wrapper


class Nuclei(data_model.WaluigiTool):
    """
    Nuclei vulnerability scanner tool configuration.

    This class configures the Nuclei vulnerability scanner for integration with the
    Waluigi framework. Nuclei is a fast and flexible vulnerability scanner that uses
    YAML-based templates to identify security issues in web applications and services.

    The tool is configured for active scanning with HTTP technology fingerprinting
    and vulnerability detection capabilities.

    Attributes:
        name (str): Tool identifier name
        description (str): Human-readable tool description
        project_url (str): Official project URL
        collector_type (str): Type of collection (ACTIVE)
        scan_order (int): Execution order in scan chain
        args (str): Default command line arguments
        scan_func (callable): Function to execute scans
        import_func (callable): Function to import results

    Example:
        >>> nuclei_tool = Nuclei()
        >>> print(nuclei_tool.name)
        'nuclei'
        >>> nuclei_tool.scan_func(scan_input)
        True
    """

    def __init__(self) -> None:
        """
        Initialize Nuclei tool configuration.

        Sets up the tool with default parameters for vulnerability scanning,
        including fingerprinting templates and rate limiting.
        """
        self.name: str = 'nuclei'
        self.description: str = 'Nuclei is a fast and flexible vulnerability scanner based on simple YAML based DSL. It allows users to create custom templates for scanning various protocols and services.'
        self.project_url: str = 'https://github.com/projectdiscovery/nuclei'
        self.collector_type: str = data_model.CollectorType.ACTIVE.value
        self.scan_order: int = 7
        self.args: str = "-ni -pt http -rl 50 -t http/technologies/fingerprinthub-web-fingerprints.yaml"
        self.input_records = [data_model.ServerRecordType.HTTP_ENDPOINT_DATA]
        self.output_records = [
            data_model.ServerRecordType.COLLECTION_MODULE,
            data_model.ServerRecordType.COLLECTION_MODULE_OUTPUT,
            data_model.ServerRecordType.WEB_COMPONENT,
            data_model.ServerRecordType.VULNERABILITY
        ]
        self.scan_func = Nuclei.nuclei_scan_func
        self.import_func = Nuclei.nuclei_import

    @staticmethod
    def nuclei_scan_func(scan_input: data_model.ScheduledScan) -> bool:
        """
        Execute Nuclei vulnerability scan.

        Initiates a Nuclei scan using Luigi task orchestration. The scan targets
        are processed from the scheduled scan input and results are stored for
        subsequent import processing.

        Args:
            scan_input (data_model.ScheduledScan): Scheduled scan configuration
                containing target information and scan parameters

        Returns:
            bool: True if scan completed successfully, False otherwise

        Example:
            >>> scan_input = ScheduledScan(...)
            >>> success = Nuclei.nuclei_scan_func(scan_input)
            >>> print(success)
            True
        """
        luigi_run_result = luigi.build([NucleiScan(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True

    @staticmethod
    def nuclei_import(scan_input: data_model.ScheduledScan) -> bool:
        """
        Import and process Nuclei scan results.

        Processes the output from a completed Nuclei scan, parsing JSON results
        and importing discovered vulnerabilities and components into the data model.

        Args:
            scan_input (data_model.ScheduledScan): Scheduled scan configuration
                containing scan results to import

        Returns:
            bool: True if import completed successfully, False otherwise

        Example:
            >>> scan_input = ScheduledScan(...)
            >>> success = Nuclei.nuclei_import(scan_input)
            >>> print(success)
            True
        """
        luigi_run_result = luigi.build([ImportNucleiOutput(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


class NucleiScan(luigi.Task):
    """
    Luigi task for executing Nuclei vulnerability scans.

    This task orchestrates the execution of Nuclei scans against target endpoints,
    handling input file preparation, command execution, and output collection.
    The task processes host-port mappings to construct target URLs and executes
    Nuclei with appropriate templates and configuration.

    The scan supports both IP addresses and domain names, constructing appropriate
    URLs for HTTP/HTTPS endpoints. Only base URLs (root paths) are scanned - URLs
    with specific paths are filtered out to focus vulnerability scanning on the
    primary endpoints. Results are collected and prepared for import processing.

    Attributes:
        scan_input (luigi.Parameter): Scheduled scan configuration parameter

    Example:
        >>> scan_task = NucleiScan(scan_input=scheduled_scan)
        >>> scan_task.run()
        # Executes Nuclei scan and saves results
    """

    scan_input: luigi.Parameter = luigi.Parameter()

    def output(self) -> luigi.LocalTarget:
        """
        Define output file target for scan results.

        Creates the output file path where scan results will be stored,
        incorporating scan ID and optional module ID for uniqueness.

        Returns:
            luigi.LocalTarget: Output file target for scan results

        Example:
            >>> task = NucleiScan(scan_input=scan)
            >>> target = task.output()
            >>> print(target.path)
            '/path/to/outputs/nuclei_outputs_scan123'
        """
        scheduled_scan_obj = self.scan_input
        scan_id: str = scheduled_scan_obj.id

        #  Init directory
        tool_name: str = scheduled_scan_obj.current_tool.name
        dir_path: str = scan_utils.init_tool_folder(
            tool_name, 'outputs', scan_id)

        mod_str: str = ''
        if scheduled_scan_obj.scan_data.module_id:
            module_id: str = str(scheduled_scan_obj.scan_data.module_id)
            mod_str = "_" + module_id

        nuclei_outputs_file: str = dir_path + os.path.sep + \
            "nuclei_outputs_" + scan_id + mod_str
        return luigi.LocalTarget(nuclei_outputs_file)

    def run(self) -> None:
        """
        Execute the Nuclei vulnerability scan.

        Processes target endpoints, prepares input files, and executes Nuclei
        with configured templates and arguments. Handles both IP addresses and
        domain names, constructing appropriate URLs for scanning.

        The method filters URLs to only scan base URLs (root paths), skipping
        any URLs with specific paths to focus vulnerability scanning on the
        primary endpoints.

        The method:
        1. Sets up environment variables and paths
        2. Processes target host-port mappings 
        3. Constructs target URLs (HTTP/HTTPS) - filtering to base URLs only
        4. Creates input file for Nuclei
        5. Executes Nuclei scan command
        6. Collects and stores results

        Raises:
            Exception: If scan execution fails or output cannot be written

        Example:
            >>> task = NucleiScan(scan_input=scheduled_scan)
            >>> task.run()
            # Executes scan and writes results to output file
        """
        scheduled_scan_obj = self.scan_input

        # Make sure template path exists
        my_env: Dict[str, str] = os.environ.copy()
        use_shell: bool = False
        if os.name == 'nt':
            nuclei_template_root: str = '%%userprofile%%'
            use_shell = True
        else:
            my_env["HOME"] = "/opt"
            # nuclei_template_root = '/opt'

        # Get output file path
        output_file_path: str = self.output().path
        output_dir: str = os.path.dirname(output_file_path)

        total_endpoint_set: Set[str] = set()
        # endpoint_port_obj_map: Dict[str, Dict[str, Any]] = {}
        nuclei_output_file: Optional[str] = None

        custom_args: Optional[List[str]] = None
        if scheduled_scan_obj.current_tool.args:
            custom_args = scheduled_scan_obj.current_tool.args.split(" ")

        # Get all the endpoints to scan - filter to only base URLs (skip non-default paths)
        all_endpoint_port_obj_map = scheduled_scan_obj.scan_data.get_urls()
        endpoint_port_obj_map = {}

        # Filter URLs to only include base URLs (path is None or "/")
        for url, port_data in all_endpoint_port_obj_map.items():
            # Only include URLs with no specific path or root path
            if port_data.get('path') is None or port_data.get('path') == '/':
                endpoint_port_obj_map[url] = port_data

        total_endpoint_set = set(endpoint_port_obj_map.keys())

        # Write to nuclei input file if endpoints exist
        counter: int = 0
        if len(total_endpoint_set) > 0:

            mod_str: str = ''
            if scheduled_scan_obj.scan_data.module_id:
                module_id: str = str(scheduled_scan_obj.scan_data.module_id)
                mod_str = "_" + module_id

            nuclei_scan_input_file_path: str = (
                output_dir + os.path.sep + "nuclei_scan_in" + mod_str).strip()

            # Write target endpoints to input file
            with open(nuclei_scan_input_file_path, 'w') as file_fd:
                for endpoint in total_endpoint_set:
                    file_fd.write(endpoint + '\n')

            # Prepare output file path
            nuclei_output_file = output_dir + os.path.sep + \
                "nuclei_scan_out" + mod_str + "_" + str(counter)

            # Build command arguments
            command: List[str] = []
            if os.name != 'nt':
                command.append("sudo")

            command_inner: List[str] = [
                "nuclei",
                "-jsonl",
                "-l",
                nuclei_scan_input_file_path,
                "-o",
                nuclei_output_file,
            ]

            # Add custom args
            if custom_args:
                command_inner.extend(custom_args)

            command.extend(command_inner)

            # Execute scan with process tracking
            callback_with_tool_id = partial(
                scheduled_scan_obj.register_tool_executor, scheduled_scan_obj.current_tool_instance_id)

            future_inst = scan_utils.executor.submit(
                process_wrapper, cmd_args=command, use_shell=use_shell, my_env=my_env, pid_callback=callback_with_tool_id, store_output=True)

            # Wait for scan completion
            ret_dict = future_inst.result()
            if ret_dict and 'exit_code' in ret_dict:
                exit_code = ret_dict['exit_code']
                if exit_code != 0:
                    err_msg = ''
                    if 'stderr' in ret_dict and ret_dict['stderr']:
                        err_msg = ret_dict['stderr']
                    logging.getLogger(__name__).error(
                        "Nuclei scan for scan ID %s exited with code %d: %s" % (scheduled_scan_obj.id, exit_code, err_msg))
                    raise RuntimeError("Nuclei scan for scan ID %s exited with code %d: %s" % (
                        scheduled_scan_obj.id, exit_code, err_msg))

        # Prepare results dictionary
        results_dict: Dict[str, Any] = {
            'endpoint_port_obj_map': endpoint_port_obj_map,
            'output_file_path': nuclei_output_file
        }

        # Write output file
        with open(output_file_path, 'w') as file_fd:
            file_fd.write(json.dumps(results_dict))


@inherits(NucleiScan)
class ImportNucleiOutput(data_model.ImportToolXOutput):
    """
    Luigi task for importing and processing Nuclei scan results.

    This task processes the JSON output from Nuclei scans, parsing vulnerability
    data and importing discovered components, vulnerabilities, and modules into
    the data model. It handles various Nuclei template types including CVE
    templates and fingerprinting templates.

    The import process categorizes findings into:
    - Web components (from fingerprinting templates)
    - Vulnerabilities (from CVE templates)
    - Collection modules (for custom templates)
    - Module outputs (detailed scan results)

    Attributes:
        Inherits all attributes from NucleiScan task

    Example:
        >>> import_task = ImportNucleiOutput(scan_input=scheduled_scan)
        >>> import_task.run()
        # Processes and imports Nuclei results
    """

    def requires(self) -> NucleiScan:
        """
        Specify task dependencies.

        This task requires the NucleiScan task to complete before it can
        process the scan results.

        Returns:
            NucleiScan: The required scan task that must complete first
        """
        return NucleiScan(scan_input=self.scan_input)

    def run(self) -> None:
        """
        Import and process Nuclei scan results.

        Processes the JSON output from Nuclei scans, parsing various template
        results and importing them as appropriate data model objects. The method
        handles different template types and creates corresponding objects:

        - fingerprinthub-web-fingerprints: Creates WebComponent objects
        - CVE templates: Creates Vuln objects
        - Custom templates: Creates CollectionModule objects
        - All templates: Creates CollectionModuleOutput objects

        The method also handles module-specific processing when a module ID
        is present in the scan configuration.

        Raises:
            Exception: If result import fails or data model objects cannot be created

        Example:
            >>> task = ImportNucleiOutput(scan_input=scheduled_scan)
            >>> task.run()
            # Imports vulnerabilities, components, and modules
        """
        scheduled_scan_obj = self.scan_input
        tool_instance_id: int = scheduled_scan_obj.current_tool_instance_id
        scope_obj = scheduled_scan_obj.scan_data

        # Import the ports to the manager
        tool_id: int = scheduled_scan_obj.current_tool.id

        nuclei_output_file: str = self.input().path
        with open(nuclei_output_file, 'r') as file_fd:
            data: str = file_fd.read()

        ret_arr: List[Any] = []
        if len(data) > 0:
            scan_data_dict: Dict[str, Any] = json.loads(data)
            endpoint_port_obj_map: Dict[str, Dict[str, Any]
                                        ] = scan_data_dict['endpoint_port_obj_map']
            output_file_path: Optional[str] = scan_data_dict.get(
                'output_file_path')

            # Read nuclei output if file exists
            if output_file_path:
                obj_arr: List[Dict[str, Any]] = scan_utils.parse_json_blob_file(
                    output_file_path)

                for nuclei_scan_result in obj_arr:
                    if 'url' not in nuclei_scan_result:
                        continue

                    endpoint: str = nuclei_scan_result['url']

                    # Get the port object that maps to this url
                    if endpoint not in endpoint_port_obj_map:
                        logging.getLogger(__name__).debug("Endpoint not in map: %s %s" %
                                                          (endpoint, str(endpoint_port_obj_map)))
                        continue

                    port_obj: Dict[str, int] = endpoint_port_obj_map[endpoint]
                    port_id: int = port_obj['port_id']

                    if 'template-id' not in nuclei_scan_result:
                        continue

                    template_id: str = nuclei_scan_result['template-id'].lower()

                    # Handle fingerprinting templates
                    if template_id == 'fingerprinthub-web-fingerprints':
                        if 'matcher-name' in nuclei_scan_result:
                            matcher_name: str = nuclei_scan_result['matcher-name'].lower(
                            )

                            # Add web component
                            component_obj = data_model.WebComponent(
                                parent_id=port_id)
                            component_obj.collection_tool_instance_id = tool_instance_id
                            component_obj.name = matcher_name
                            ret_arr.append(component_obj)

                    # Handle CVE templates
                    elif template_id.startswith("cve-"):
                        # Add vulnerability
                        vuln_obj = data_model.Vuln(parent_id=port_id)
                        vuln_obj.collection_tool_instance_id = tool_instance_id
                        vuln_obj.name = template_id
                        ret_arr.append(vuln_obj)

                    # Extract module arguments from template
                    module_args: Optional[str] = None
                    if 'template' in nuclei_scan_result:
                        module_args = nuclei_scan_result['template']

                    module_id: Optional[str] = None

                    # Handle module-specific processing
                    if scope_obj.module_id:
                        module_id = str(scope_obj.module_id)

                        # Parse output and add components if present
                        output_components = scope_obj.module_outputs
                        for output_component in output_components:
                            if output_component.name in str(nuclei_scan_result).lower():
                                component_obj = data_model.WebComponent(
                                    parent_id=port_id)
                                component_obj.collection_tool_instance_id = tool_instance_id
                                component_obj.name = output_component.name
                                ret_arr.append(component_obj)
                    else:
                        # Add collection module for non-module scans
                        module_obj = data_model.CollectionModule(
                            parent_id=tool_id)
                        module_obj.collection_tool_instance_id = tool_instance_id
                        module_obj.name = template_id
                        module_obj.args = module_args
                        ret_arr.append(module_obj)
                        module_id = module_obj.id

                    # Add module output for all scan results
                    if module_id:
                        module_output_obj = data_model.CollectionModuleOutput(
                            parent_id=module_id)
                        module_output_obj.collection_tool_instance_id = tool_instance_id
                        module_output_obj.output = nuclei_scan_result
                        module_output_obj.port_id = port_id
                        ret_arr.append(module_output_obj)

        # Import, Update, & Save all collected results
        self.import_results(scheduled_scan_obj, ret_arr)
