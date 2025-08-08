"""
Waluigi Subfinder Scan Module

This module integrates Subfinder, a subdomain discovery tool, into the Waluigi
security scanning framework. It provides passive subdomain enumeration using
various online sources and APIs.

Subfinder is a subdomain discovery tool that finds valid subdomains for websites
using passive online sources. It has a simple, modular architecture and is
optimized for speed.

The module includes:
- Subfinder tool integration and configuration
- Subdomain discovery and DNS resolution
- API key management for enhanced results
- Luigi task orchestration for scan workflows
- Domain-to-IP mapping and data processing

Classes:
    Subfinder: Main tool class for subdomain discovery
    SubfinderScan: Luigi task for executing subdomain scans  
    SubfinderImport: Luigi task for importing scan results

Functions:
    subfinder_wrapper: Wrapper for Subfinder execution
    get_subfinder_input: Prepare input data for Subfinder
    update_config_file: Manage API key configuration
    dns_wrapper: Perform DNS resolution for discovered domains
"""

from functools import partial
import json
import os
import netaddr
import socket
import luigi
import traceback
import os.path
import yaml
import logging
from typing import List, Dict, Set, Optional, Any, Tuple

from luigi.util import inherits
from waluigi import scan_utils
from waluigi import data_model
from waluigi.proc_utils import process_wrapper


class Subfinder(data_model.WaluigiTool):
    """
    Subfinder tool integration for passive subdomain discovery.

    This class integrates the Subfinder tool into the Waluigi framework, providing
    passive subdomain enumeration capabilities using various online sources and APIs.
    Subfinder is optimized for speed and uses a modular architecture.

    The tool supports multiple data sources including:
    - Certificate Transparency logs
    - Search engines (Google, Bing, Yahoo)
    - DNS aggregators and databases
    - Security vendors APIs (Shodan, SecurityTrails, Chaos)

    Attributes:
        name (str): Tool name identifier
        description (str): Detailed tool description
        project_url (str): URL to the Subfinder project
        collector_type (int): Type of collection (PASSIVE)
        scan_order (int): Execution order in scan workflow
        args (str): Default command-line arguments
        scan_func (callable): Function to execute subdomain scans
        import_func (callable): Function to import scan results

    Example:
        >>> subfinder = Subfinder()
        >>> print(subfinder.name)  # "subfinder"
        >>> print(subfinder.collector_type)  # PASSIVE collection type
    """

    def __init__(self) -> None:
        """
        Initialize the Subfinder tool configuration.

        Sets up the tool with default parameters, scan functions, and metadata
        required for integration with the Waluigi scanning framework.
        """
        self.name = 'subfinder'
        self.description = 'subfinder is a subdomain discovery tool that returns valid subdomains for websites, using passive online sources. It has a simple, modular architecture and is optimized for speed.'
        self.project_url = 'https://github.com/projectdiscovery/subfinder'
        self.collector_type = data_model.CollectorType.PASSIVE.value
        self.scan_order = 1
        self.args = "-all"
        self.input_records = [data_model.ServerRecordType.DOMAIN]
        self.output_records = [
            data_model.ServerRecordType.HOST, data_model.ServerRecordType.DOMAIN]
        self.scan_func = Subfinder.subfinder_lookup
        self.import_func = Subfinder.subfinder_import

    @staticmethod
    def subfinder_lookup(scan_input: Any) -> bool:
        """
        Execute Subfinder subdomain discovery scan.

        This static method orchestrates the Subfinder scanning process using Luigi
        task management. It builds and executes a SubfinderScan task with the
        provided scan input configuration.

        Args:
            scan_input (Any): Scan input object containing scan configuration and context

        Returns:
            bool: True if scan completed successfully, False if scan failed

        Example:
            >>> scan_config = get_scan_input()
            >>> success = Subfinder.subfinder_lookup(scan_config)
            >>> if success:
            ...     print("Subfinder scan completed")
        """
        luigi_run_result = luigi.build([SubfinderScan(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True

    @staticmethod
    def subfinder_import(scan_input: Any) -> bool:
        """
        Import and process Subfinder scan results.

        This static method handles the import of Subfinder scan results into the
        data model. It builds and executes a SubfinderImport task to process
        the discovered subdomains and their associated IP addresses.

        Args:
            scan_input (Any): Scan input object containing scan configuration and context

        Returns:
            bool: True if import completed successfully, False if import failed

        Example:
            >>> scan_config = get_scan_input()
            >>> success = Subfinder.subfinder_import(scan_config)
            >>> if success:
            ...     print("Subfinder results imported")
        """
        luigi_run_result = luigi.build([SubfinderImport(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


def subfinder_wrapper(scheduled_scan_obj: Any, scan_output_file_path: str,
                      command: List[str], use_shell: bool, my_env: Dict[str, str]) -> List[Dict[str, str]]:
    """
    Execute Subfinder command and parse results.

    This function wraps the execution of a Subfinder command, handles the process
    execution, and parses the JSON output to extract domain and IP information.

    Args:
        scheduled_scan_obj (Any): Scheduled scan object for tracking execution
        scan_output_file_path (str): Path to the output file for Subfinder results
        command (List[str]): Command array to execute Subfinder
        use_shell (bool): Whether to use shell for command execution
        my_env (Dict[str, str]): Environment variables for the process

    Returns:
        List[Dict[str, str]]: List of dictionaries containing 'ip' and 'domain' keys
                             for each discovered subdomain

    Example:
        >>> cmd = ["subfinder", "-d", "example.com", "-json"]
        >>> results = subfinder_wrapper(scan_obj, "/tmp/output.json", cmd, False, env)
        >>> for result in results:
        ...     print(f"Domain: {result['domain']}, IP: {result['ip']}")

    Note:
        Registers the tool executor with the scan object for process tracking
    """

    ret_list = []
    # Call subfinder process
    callback_with_tool_id = partial(
        scheduled_scan_obj.register_tool_executor, scheduled_scan_obj.current_tool_instance_id)

    ret_dict = process_wrapper(
        command, use_shell, my_env, callback_with_tool_id)

    if ret_dict and 'exit_code' in ret_dict:
        exit_code = ret_dict['exit_code']
        if exit_code != 0:
            err_msg = ''
            if 'stderr' in ret_dict and ret_dict['stderr']:
                err_msg = ret_dict['stderr']
            logging.getLogger(__name__).error(
                "Subfinder scan for scan ID %s exited with code %d: %s" % (scheduled_scan_obj.id, exit_code, err_msg))
            raise RuntimeError("Subfinder scan for scan ID %s exited with code %d: %s" % (
                scheduled_scan_obj.id, exit_code, err_msg))

    # Parse the output
    obj_arr = scan_utils.parse_json_blob_file(scan_output_file_path)
    for domain_entry in obj_arr:
        domain_name = domain_entry['host']
        ip_str = domain_entry['ip']
        ret_list.append({'ip': ip_str, 'domain': domain_name})

    return ret_list


def get_subfinder_input(scheduled_scan_obj: Any) -> Dict[str, str]:
    """
    Prepare input data for Subfinder subdomain discovery.

    This function extracts domain names from the scan scope and creates an input
    file containing domains to be processed by Subfinder. It filters domains
    based on their tags (SCOPE and LOCAL).

    Args:
        scheduled_scan_obj (Any): Scheduled scan object containing scan data and configuration

    Returns:
        Dict[str, str]: Dictionary containing 'input_path' key with path to the input file

    Example:
        >>> scan_obj = get_scheduled_scan()
        >>> input_data = get_subfinder_input(scan_obj)
        >>> print(input_data['input_path'])  # "/tmp/dns_urls_scan123"

    Note:
        Creates a temporary file with one domain per line for Subfinder processing.
        Only includes domains tagged as SCOPE or LOCAL.
    """

    scan_id = scheduled_scan_obj.id
    tool_name = scheduled_scan_obj.current_tool.name
    dir_path = scan_utils.init_tool_folder(tool_name, 'inputs', scan_id)
    dns_url_file = dir_path + os.path.sep + "dns_urls_" + scan_id

    scope_obj = scheduled_scan_obj.scan_data
    domain_list = scope_obj.get_domains(
        [data_model.RecordTag.SCOPE.value, data_model.RecordTag.LOCAL.value])

    with open(dns_url_file, 'w') as file_fd:
        for domain in domain_list:
            file_fd.write(domain.name + '\n')

    # Write the output
    scan_dict = {'input_path': dns_url_file}
    return scan_dict


def update_config_file(collection_tools: Optional[List[Any]], my_env: Dict[str, str]) -> None:
    """
    Update Subfinder configuration file with API keys.

    This function manages the Subfinder provider configuration file, updating it
    with API keys from collection tools to enhance subdomain discovery results.
    Supports Chaos, Shodan, and SecurityTrails API keys.

    Args:
        collection_tools (Optional[List[Any]]): List of collection tool instances with API keys
                                              If None, clears all API keys from config
        my_env (Dict[str, str]): Environment variables for process execution

    Returns:
        None: Updates the configuration file in place

    Example:
        >>> tools = [chaos_tool, shodan_tool, sectrails_tool]
        >>> update_config_file(tools, os.environ.copy())
        >>> # Configuration file now contains API keys
        >>> update_config_file(None, os.environ.copy())  # Clear keys

    Note:
        - Creates initial config file if it doesn't exist
        - Config file location: ~/.config/subfinder/provider-config.yaml
        - Supported providers: chaos, shodan, securitytrails
    """

    home_dir = os.path.expanduser('~')
    config_file_path = "%s/.config/subfinder/provider-config.yaml" % home_dir

    # If no file then run subfinder to generate the template
    if os.path.isfile(config_file_path) == False:
        cmd_arr = ["subfinder", "-d", "localhost", "-timeout", "1"]
        future = scan_utils.executor.submit(
            process_wrapper, cmd_args=cmd_arr, my_env=my_env)
        future.result()

        cmd_arr = ["subfinder", "-h"]
        future = scan_utils.executor.submit(
            process_wrapper, cmd_args=cmd_arr, my_env=my_env)
        future.result()

    # Update provider config file
    with open(config_file_path, 'r') as file_fd:
        data = yaml.safe_load(file_fd)

    data['chaos'] = []
    data['shodan'] = []
    data['securitytrails'] = []

    api_key_arr = ['chaos', 'shodan', 'securitytrails']
    if collection_tools:
        for collection_tool_inst in collection_tools:
            collection_tool = collection_tool_inst.collection_tool
            if collection_tool.name in api_key_arr and collection_tool.api_key:
                data[collection_tool.name] = [collection_tool.api_key]

    # Write to config file
    with open(config_file_path, 'w') as yaml_file:
        yaml_file.write(yaml.dump(data, default_flow_style=False))


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
        futures_map[domain] = scan_utils.executor.submit(
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


class SubfinderScan(luigi.Task):
    """
    Luigi task for executing Subfinder subdomain discovery scans.

    This task orchestrates the complete Subfinder scanning workflow including:
    - Input preparation with domain lists
    - API key configuration management
    - Concurrent Subfinder execution for multiple domains
    - DNS resolution for discovered and input domains
    - Results aggregation and output file generation

    The task handles multiple domains concurrently and integrates with various
    API providers (Chaos, Shodan, SecurityTrails) for enhanced results.

    Attributes:
        scan_input (luigi.Parameter): Scheduled scan object containing configuration

    Example:
        >>> task = SubfinderScan(scan_input=scheduled_scan)
        >>> output_target = task.output()
        >>> task.run()  # Execute subdomain discovery
    """

    scan_input = luigi.Parameter()

    def output(self) -> luigi.LocalTarget:
        """
        Define the output target for Subfinder scan results.

        Creates the output file path for storing Subfinder scan results in JSON format.
        The file is stored in the tool's output directory within the scan workspace.

        Returns:
            luigi.LocalTarget: Target file for storing subdomain discovery results

        Example:
            >>> task = SubfinderScan(scan_input=scan_obj)
            >>> target = task.output()
            >>> print(target.path)  # "/path/to/outputs/subfinder_outputs_scan123"
        """

        scheduled_scan_obj = self.scan_input
        scan_id = scheduled_scan_obj.id

        # Init directory
        tool_name = scheduled_scan_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)

        # path to input file
        dns_outputs_file = dir_path + os.path.sep + "subfinder_outputs_" + scan_id
        return luigi.LocalTarget(dns_outputs_file)

    def run(self) -> None:
        """
        Execute the Subfinder subdomain discovery scan.

        This method performs the complete Subfinder scanning workflow:
        1. Prepare input domains from scan scope
        2. Configure API keys for enhanced results
        3. Execute Subfinder for each domain concurrently
        4. Perform DNS resolution for discovered subdomains
        5. Aggregate results and save to output file

        The method handles:
        - Environment variable setup for different operating systems
        - API key configuration management
        - Concurrent execution with futures tracking
        - Error handling and resource cleanup
        - DNS resolution for parent domains

        Returns:
            None: Results are written to the output file

        Example:
            >>> task = SubfinderScan(scan_input=scan_config)
            >>> task.run()  # Executes complete subdomain discovery workflow

        Note:
            - Creates unique output files for each domain scan
            - Registers tool executors for process tracking
            - Cleans up API keys after scanning
            - Performs additional DNS resolution for input domains
        """

        scheduled_scan_obj = self.scan_input
        dns_scan_obj = get_subfinder_input(scheduled_scan_obj)

        tool_args = scheduled_scan_obj.current_tool.args
        if tool_args:
            tool_args = tool_args.split(" ")

        # Ensure output folder exists
        meta_file_path = self.output().path
        dir_path = os.path.dirname(meta_file_path)

        # Write out meta data file
        ret_list = []

        subfinder_domain_list = dns_scan_obj['input_path']
        # api_keys = dns_scan_obj['api_keys']

        # Add env variables for HOME
        my_env = os.environ.copy()

        use_shell = False
        if os.name != 'nt':
            home_dir = os.path.expanduser('~')
            my_env["HOME"] = home_dir

        # Set the API keys
        update_config_file(
            list(scheduled_scan_obj.collection_tool_map.values()), my_env)

        futures = []

        # Add the domains from the wildcards
        with open(subfinder_domain_list, 'r') as file_fd:
            sub_lines = file_fd.readlines()

        # Add the lines
        domain_set = set()
        counter = 0
        if len(sub_lines) > 0:
            for line in sub_lines:
                domain_str = line.strip()
                if len(domain_str) > 0 and domain_str not in domain_set:

                    # Add to the set
                    domain_set.add(domain_str)
                    # Create unique output file path
                    scan_output_file_path = dir_path + os.path.sep + \
                        "subfinder_results_" + str(counter) + ".json"

                    command = []
                    command_arr = [
                        "subfinder",
                        "-json",
                        "-d",
                        domain_str,
                        "-o",
                        scan_output_file_path,
                        "-active",
                        "-ip"
                    ]

                    command.extend(command_arr)

                    # Add script args
                    if tool_args and len(tool_args) > 0:
                        command.extend(tool_args)

                    futures.append(scan_utils.executor.submit(
                        subfinder_wrapper, scheduled_scan_obj, scan_output_file_path, command, use_shell, my_env))

                    counter += 1

            # Register futures
            scan_proc_inst = data_model.ToolExecutor(futures)
            scheduled_scan_obj.register_tool_executor(
                scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

            for future in futures:
                temp_list = future.result()
                ret_list.extend(temp_list)

        # Reset the API keys
        update_config_file(None, my_env)

        # Resolve the parent domains too
        if len(domain_set) > 0:
            ret_list.extend(dns_wrapper(domain_set))

        # Write the output file
        with open(meta_file_path, 'w') as output_fd:
            output_fd.write(json.dumps({'domain_list': ret_list}))


@inherits(SubfinderScan)
class SubfinderImport(data_model.ImportToolXOutput):
    """
    Luigi task for importing and processing Subfinder scan results.

    This task handles the import of Subfinder scan results into the data model,
    converting discovered domains and IP addresses into structured Host and Domain
    objects. It processes the JSON output from SubfinderScan and creates appropriate
    data model objects.

    The import process includes:
    - Reading and parsing Subfinder JSON output
    - Converting domain-to-IP mappings to IP-to-domain mappings
    - Creating Host objects for discovered IP addresses
    - Creating Domain objects for discovered subdomains
    - Establishing parent-child relationships between hosts and domains

    Inherits from:
        SubfinderScan: Inherits scan input parameter
        ImportToolXOutput: Provides result import functionality

    Example:
        >>> import_task = SubfinderImport(scan_input=scheduled_scan)
        >>> import_task.run()  # Import and process scan results
    """

    def requires(self) -> SubfinderScan:
        """
        Define task dependencies - requires SubfinderScan to complete first.

        Returns:
            SubfinderScan: The scan task that must complete before import

        Example:
            >>> import_task = SubfinderImport(scan_input=scan_obj)
            >>> dependency = import_task.requires()
            >>> print(type(dependency).__name__)  # "SubfinderScan"
        """
        # Requires subfinderScan Task to be run prior
        return SubfinderScan(scan_input=self.scan_input)

    def run(self) -> None:
        """
        Import and process Subfinder scan results into the data model.

        This method performs the complete import workflow:
        1. Read JSON output from SubfinderScan task
        2. Parse domain and IP address mappings
        3. Create Host objects for each unique IP address
        4. Create Domain objects for each discovered subdomain
        5. Establish proper parent-child relationships
        6. Import results into the scan data structure

        The method handles:
        - JSON parsing and error handling
        - IP address validation and object creation
        - IPv4 and IPv6 address support
        - Domain object creation with proper relationships
        - Tool instance ID tracking for data lineage

        Returns:
            None: Results are imported into the scan data structure

        Example:
            >>> import_task = SubfinderImport(scan_input=scan_config)
            >>> import_task.run()  # Process and import discovered subdomains

        Note:
            - Converts domain-to-IP mappings to IP-to-domain for efficiency
            - Creates one Host object per unique IP address
            - Associates multiple Domain objects with each Host
            - Preserves tool instance ID for data tracking
        """

        scheduled_scan_obj = self.scan_input
        tool_instance_id = scheduled_scan_obj.current_tool_instance_id

        # Read the Subfinder output file
        subfinder_output_file = self.input().path
        with open(subfinder_output_file, 'r') as file_fd:
            data = file_fd.read()

        obj_map: Dict[str, Any] = {}
        if len(data) > 0:
            domain_map = json.loads(data)

            if 'domain_list' in domain_map:
                domain_list = domain_map['domain_list']

                # Create IP-to-domains mapping for efficient processing
                ip_map: Dict[str, Set[str]] = {}

                # Convert from domain-to-IP map to IP-to-domain map
                for domain_entry in domain_list:
                    # Extract domain and IP information
                    domain_str = domain_entry['domain']
                    ip_str = domain_entry['ip']

                    # Group domains by IP address
                    if ip_str in ip_map:
                        domain_list_for_ip = ip_map[ip_str]
                    else:
                        domain_list_for_ip = set()
                        ip_map[ip_str] = domain_list_for_ip

                    domain_list_for_ip.add(domain_str)

                # Process each unique IP address
                for ip_addr in ip_map:
                    domain_set = ip_map[ip_addr]
                    domains = list(domain_set)

                    # Create IP address object for validation
                    ip_object = netaddr.IPAddress(ip_addr)

                    # Create Host object for the IP address
                    host_obj = data_model.Host()
                    host_obj.collection_tool_instance_id = tool_instance_id

                    # Set appropriate IP address field based on version
                    if ip_object.version == 4:
                        host_obj.ipv4_addr = str(ip_object)
                    elif ip_object.version == 6:
                        host_obj.ipv6_addr = str(ip_object)

                    # Add host to object map
                    obj_map[host_obj.id] = host_obj

                    # Create Domain objects for each domain associated with this IP
                    for domain in domains:
                        domain_obj = data_model.Domain(parent_id=host_obj.id)
                        domain_obj.collection_tool_instance_id = tool_instance_id
                        domain_obj.name = domain

                        # Add domain to object map
                        obj_map[domain_obj.id] = domain_obj

        # Convert object map to list for import
        ret_arr = list(obj_map.values())

        # Import results into scan data structure
        scheduled_scan_obj = self.scan_input
        self.import_results(scheduled_scan_obj, ret_arr)
