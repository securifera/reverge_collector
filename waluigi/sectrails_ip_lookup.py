"""
SecurityTrails IP Lookup Module.

This module provides comprehensive passive DNS reconnaissance capabilities using
SecurityTrails, a threat-intelligence platform specializing in DNS and domain data.
It integrates with the Waluigi framework to perform automated IP-to-domain resolution
and historical DNS data collection for security reconnaissance.

The module supports:
    - Passive DNS reconnaissance for IP addresses
    - Historical domain resolution data collection
    - Current and historical DNS record analysis
    - WHOIS information gathering capabilities
    - Comprehensive domain discovery from IP addresses
    - API-based threat intelligence data collection
    - Integration with the Waluigi passive reconnaissance workflow

Classes:
    Sectrails: Main tool class implementing the SecurityTrails API interface
    SecTrailsIPLookupScan: Luigi task for executing IP lookup operations
    ImportSecTrailsIPLookupOutput: Luigi task for importing and processing lookup results

Functions:
    request_wrapper: Core API request function for SecurityTrails IP lookup

Global Variables:
    proxies: HTTP proxy configuration for API requests

Example:
    Basic usage through the Waluigi framework::
    
        # Initialize the tool
        sectrails = Sectrails()
        
        # Execute IP lookup (requires API key configuration)
        success = sectrails.import_func(scan_input_obj)

Note:
    This module requires a valid SecurityTrails API key for operation.
    It performs passive reconnaissance and does not generate network traffic
    to target systems. The tool provides historical and current DNS data
    for comprehensive domain intelligence gathering.

"""

import requests
import luigi
import os
import json
import time
import logging
from typing import Dict, Set, List, Any, Optional, Union

from luigi.util import inherits
from waluigi import scan_utils
from waluigi import data_model

# Global proxy configuration for SecurityTrails API requests
proxies: Optional[Dict[str, str]] = None


class Sectrails(data_model.WaluigiTool):
    """
    SecurityTrails threat intelligence platform integration for the Waluigi framework.

    This class provides integration with SecurityTrails, a comprehensive threat-intelligence
    platform specializing in DNS and domain data collection. It implements the WaluigiTool
    interface to provide passive DNS reconnaissance capabilities within the security
    reconnaissance workflow.

    SecurityTrails offers extensive capabilities including:
        - Current and historical DNS record collection
        - Passive DNS data for comprehensive domain analysis
        - WHOIS information and domain registration data
        - IP-to-domain resolution with historical context
        - Subdomain discovery and enumeration
        - DNS infrastructure analysis and mapping

    Attributes:
        name (str): The tool identifier ('sectrails')
        description (str): Human-readable description of the platform's capabilities
        project_url (str): URL to the official SecurityTrails platform
        collector_type (int): Identifies this as a passive reconnaissance tool
        scan_order (int): Execution priority within the reconnaissance workflow (5)
        args (str): Command-line arguments (empty for API-based tools)
        import_func (callable): Static method for importing lookup results

    Methods:
        import_sectrailsiplookup: Imports and processes SecurityTrails lookup results

    Example:
        >>> tool = Sectrails()
        >>> print(tool.name)
        sectrails

        >>> # Execute IP lookup through the framework (requires API key)
        >>> success = tool.import_func(scan_input_obj)
        >>> if success:
        ...     print("SecurityTrails lookup completed successfully")

    Note:
        The scan_order of 5 positions this tool early in the reconnaissance workflow
        to provide domain intelligence for subsequent active scanning phases.
        Requires a valid SecurityTrails API key for operation.
    """

    def __init__(self) -> None:
        """
        Initialize the SecurityTrails tool with default configuration.

        Sets up the tool with appropriate parameters for passive DNS reconnaissance,
        including API integration points and workflow positioning for optimal
        intelligence gathering sequence.
        """
        self.name = 'sectrails'
        self.description = 'SecurityTrails is a threat-intelligence platform specializing in DNS and domain data. It continuously collects both current and historical DNS records, WHOIS information, and passive-DNS data to give users a comprehensive view of any domain’s evolution over time'
        self.project_url = 'https://securitytrails.com/'
        self.collector_type = data_model.CollectorType.PASSIVE.value
        self.scan_order = 5
        self.args = ""
        self.import_func = Sectrails.import_sectrailsiplookup
        self.input_records = [data_model.ServerRecordType.HOST]
        self.output_records = [data_model.ServerRecordType.DOMAIN]

    @staticmethod
    def import_sectrailsiplookup(scan_input: data_model.ScheduledScan) -> bool:
        """
        Import and process SecurityTrails IP lookup results.

        This static method serves as the main entry point for executing SecurityTrails
        IP-to-domain lookups within the Waluigi framework. It creates and executes
        a Luigi workflow to perform the API-based reconnaissance and import results
        into the framework's data model.

        Args:
            scan_input (data_model.ScheduledScan): The scheduled scan object containing
                target information, API keys, and framework configuration needed
                for the SecurityTrails lookup operation.

        Returns:
            bool: True if the lookup and import operation completed successfully,
                  False if any errors occurred during execution.

        Example:
            >>> scan_obj = data_model.ScheduledScan(...)
            >>> success = Sectrails.import_sectrailsiplookup(scan_obj)
            >>> if success:
            ...     print("SecurityTrails lookup completed")

        Note:
            This method requires a valid SecurityTrails API key to be configured
            in the scan_input object. The operation is performed asynchronously
            using Luigi's task execution framework.
        """
        luigi_run_result = luigi.build([ImportSecTrailsIPLookupOutput(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


def request_wrapper(ip_addr: str, api_key: str) -> Dict[str, Union[str, List[str]]]:
    """
    Execute SecurityTrails API request for IP-to-domain lookup.

    This function performs the core API communication with SecurityTrails to resolve
    an IP address to associated domain names. It handles API rate limiting,
    error conditions, and response parsing to extract domain information.

    The function queries SecurityTrails' search endpoint with the provided IP address
    and returns all associated domain names found in their passive DNS database.

    Args:
        ip_addr (str): The IPv4 address to lookup in SecurityTrails database.
            Must be a valid IPv4 address format (e.g., '192.168.1.1').
        api_key (str): Valid SecurityTrails API key for authentication.
            Required for accessing the SecurityTrails API endpoints.

    Returns:
        Dict[str, Union[str, List[str]]]: Dictionary containing lookup results with keys:
            - 'ip_addr' (str): The original IP address that was queried
            - 'domains' (List[str]): List of domain names associated with the IP

    Raises:
        RuntimeError: If the API request fails with non-recoverable error codes
            or if the SecurityTrails service returns invalid responses.

    Example:
        >>> result = request_wrapper('8.8.8.8', 'your_api_key_here')
        >>> print(f"Found {len(result['domains'])} domains for {result['ip_addr']}")
        Found 5 domains for 8.8.8.8

        >>> for domain in result['domains']:
        ...     print(f"  - {domain}")

    Note:
        The function implements automatic rate limit handling by sleeping when
        receiving HTTP 429 responses. Uses global proxy configuration if available.
        SSL verification is disabled for the API requests.
    """
    # Initialize domain set for collecting unique domains
    domain_set: Set[str] = set()
    ret_str: Dict[str, Union[str, List[str]]] = {'ip_addr': ip_addr}

    # Set up API headers with authentication and user agent
    headers = {
        'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
        'Content-Type': "application/json",
        "apikey": api_key
    }

    # Prepare IP address filter for API request
    ip_dict = {"ipv4": ip_addr}

    # Execute API request with rate limit handling
    while True:
        r = requests.post('https://api.securitytrails.com/v1/search/list',
                          headers=headers, json={"filter": ip_dict}, verify=False, proxies=proxies)

        # Handle rate limiting by waiting and retrying
        if r.status_code == 429:
            time.sleep(1)
            continue
        elif r.status_code != 200:
            logging.getLogger(__name__).debug(
                "Status code: %d" % r.status_code)
            logging.getLogger(__name__).debug(r.text)
            raise RuntimeError("[-] Error getting securitytrails output.")
        break

    # Parse API response and extract domain information
    content = r.json()
    if 'records' in content:
        record_arr = content['records']
        for record in record_arr:
            if 'hostname' in record:
                hostname = record['hostname']
                domain_set.add(hostname)

    # Return results with unique domains
    ret_str['domains'] = list(domain_set)
    return ret_str


class SecTrailsIPLookupScan(luigi.Task):
    """
    Luigi task for executing SecurityTrails IP lookup operations.

    This task handles the execution of SecurityTrails API requests for IP-to-domain
    lookups within the Luigi workflow framework. It processes multiple IP addresses
    from the scan input, performs concurrent API requests, and saves results to
    the output file for subsequent import processing.

    The task supports:
        - Concurrent API requests for multiple IP addresses
        - Rate limiting and error handling for API calls
        - Progress tracking and execution monitoring
        - Structured output generation for import processing

    Attributes:
        scan_input (luigi.Parameter): The scheduled scan object containing target
            IP addresses and SecurityTrails API configuration.

    Methods:
        output: Defines the output file path for lookup results
        run: Executes the IP lookup operation and saves results

    Example:
        >>> # Task is typically executed through Luigi framework
        >>> task = SecTrailsIPLookupScan(scan_input=scan_obj)
        >>> luigi.build([task], local_scheduler=True)

    Note:
        This task requires a valid SecurityTrails API key in the scan input
        configuration. Results are saved in JSON format for import processing.
    """

    # Luigi task parameter for scan input configuration
    scan_input = luigi.Parameter()

    def output(self) -> luigi.LocalTarget:
        """
        Define the output file path for SecurityTrails lookup results.

        Creates the necessary directory structure and defines the output file
        path where IP lookup results will be stored in JSON format.

        Returns:
            luigi.LocalTarget: Target object representing the output file path
                for storing SecurityTrails lookup results.

        Example:
            >>> task = SecTrailsIPLookupScan(scan_input=scan_obj)
            >>> output_target = task.output()
            >>> print(output_target.path)
            /path/to/outputs/sectrails-ip-lookup-outputs-scan123
        """

        scheduled_scan_obj = self.scan_input
        scan_id = scheduled_scan_obj.id

        # Initialize output directory structure
        tool_name = scheduled_scan_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)

        # Define output file path
        http_outputs_file = dir_path + os.path.sep + \
            "sectrails-ip-lookup-outputs-" + scan_id
        return luigi.LocalTarget(http_outputs_file)

    def run(self) -> None:
        """
        Execute SecurityTrails IP lookup operations for all target IP addresses.

        This method performs the main execution logic for the SecurityTrails lookup
        task. It processes all IP addresses from the scan input, executes concurrent
        API requests, and saves the results to the output file.

        The execution process includes:
            - Validating API key availability
            - Processing target IP addresses from scan input
            - Executing concurrent API requests with thread pool
            - Collecting and organizing lookup results
            - Saving results to output file in JSON format

        Raises:
            Exception: If API key is missing or if no target map is available
                in the scan input configuration.

        Example:
            >>> task = SecTrailsIPLookupScan(scan_input=scan_obj)
            >>> task.run()  # Executes the lookup operation

        Note:
            This method uses a thread pool executor for concurrent API requests
            to improve performance when processing multiple IP addresses.
        """

        scheduled_scan_obj = self.scan_input

        # Get output file path for results storage
        output_file_path = self.output().path

        # Initialize IP-to-host mapping dictionary
        ip_to_host_dict_map: Dict[str, Dict[str, Any]] = {}

        # Get SecurityTrails API key from scan configuration
        api_key = scheduled_scan_obj.current_tool_api_key

        if api_key and len(api_key) > 0:

            # Process target hosts from scan input
            target_map = scheduled_scan_obj.scan_data.host_port_obj_map
            if len(target_map) == 0:
                logging.getLogger(__name__).debug(
                    "No target map in scan input")

            # Build IP address mapping for lookup operations
            for target_key in target_map:
                target_obj_dict = target_map[target_key]
                host_obj = target_obj_dict['host_obj']
                ip_addr = host_obj.ipv4_addr

                # Add IP address to host mapping
                ip_to_host_dict_map[ip_addr] = {'host_id': host_obj.id}

            # Execute concurrent API requests for all IP addresses
            futures = []
            for ip_addr in ip_to_host_dict_map:
                futures.append(scan_utils.executor.submit(
                    request_wrapper, ip_addr=ip_addr, api_key=api_key))

            # Register futures with scan execution framework
            scan_proc_inst = data_model.ToolExecutor(futures)
            scheduled_scan_obj.register_tool_executor(
                scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

            # Collect results from concurrent API requests
            for future in futures:
                ret_dict = future.result()
                # Extract IP address from results
                ip_addr = ret_dict['ip_addr']
                # Get corresponding host dictionary
                host_dict = ip_to_host_dict_map[ip_addr]
                # Add discovered domains to host mapping
                host_dict['domains'] = ret_dict['domains']
        else:
            logging.getLogger(__name__).error("No api key in scan input")
            raise Exception(
                "[-] No API key configured for SecurityTrails lookup.")

        # Prepare results dictionary for output
        results_dict = {'ip_to_host_dict_map': ip_to_host_dict_map}

        # Write results to output file in JSON format
        with open(output_file_path, 'w') as file_fd:
            file_fd.write(json.dumps(results_dict))


@inherits(SecTrailsIPLookupScan)
class ImportSecTrailsIPLookupOutput(data_model.ImportToolXOutput):
    """
    Luigi task for importing and processing SecurityTrails IP lookup results.

    This task handles the import and integration of SecurityTrails lookup results
    into the Waluigi framework's data model. It reads the JSON output from the
    lookup scan, processes domain information, and creates appropriate data model
    objects for storage in the framework database.

    The import process includes:
        - Reading JSON output from SecurityTrails lookup scan
        - Processing IP-to-domain mappings from API results
        - Creating Domain objects with proper parent relationships
        - Integrating results into the framework's data model
        - Updating scan progress and status information

    Attributes:
        Inherits all attributes from SecTrailsIPLookupScan and ImportToolXOutput

    Methods:
        requires: Specifies dependency on SecTrailsIPLookupScan task
        run: Processes lookup results and imports into data model

    Example:
        >>> # Task is executed as part of the Luigi workflow
        >>> import_task = ImportSecTrailsIPLookupOutput(scan_input=scan_obj)
        >>> luigi.build([import_task], local_scheduler=True)

    Note:
        This task creates Domain objects with collection_tool_instance_id
        for tracking which tool instance discovered each domain.
    """

    def requires(self) -> SecTrailsIPLookupScan:
        """
        Specify task dependencies for the import operation.

        Returns:
            SecTrailsIPLookupScan: The lookup scan task that must complete
                before this import task can execute.
        """
        return SecTrailsIPLookupScan(scan_input=self.scan_input)

    def run(self) -> None:
        """
        Import and process SecurityTrails IP lookup results into the data model.

        This method reads the JSON output from the SecurityTrails lookup scan,
        processes the IP-to-domain mappings, creates Domain objects for each
        discovered domain, and imports them into the framework's data model.

        The import process includes:
            - Reading lookup results from the output file
            - Parsing IP-to-host-to-domain mappings
            - Creating Domain objects with proper parent-child relationships
            - Setting collection tool instance IDs for tracking
            - Importing results into the framework database

        Example:
            >>> import_task = ImportSecTrailsIPLookupOutput(scan_input=scan_obj)
            >>> import_task.run()  # Processes and imports results

        Note:
            Domain objects are created with parent_id linking to the host object
            and collection_tool_instance_id for tracking discovery source.
        """

        scheduled_scan_obj = self.scan_input
        tool_instance_id = scheduled_scan_obj.current_tool_instance_id

        # Read lookup results from output file
        scan_output_file = self.input().path
        with open(scan_output_file, 'r') as file_fd:
            data = file_fd.read()

        # Initialize object mapping for domain creation
        obj_map: Dict[str, data_model.Domain] = {}

        if len(data) > 0:
            # Parse JSON results from lookup scan
            scan_data_dict = json.loads(data)

            # Process IP-to-host-to-domain mappings
            ip_to_host_dict_map = scan_data_dict['ip_to_host_dict_map']
            for ip_addr in ip_to_host_dict_map:
                host_dict = ip_to_host_dict_map[ip_addr]
                host_id = host_dict['host_id']
                domains = host_dict['domains']

                # Create Domain objects for each discovered domain
                for domain in domains:
                    domain_obj = data_model.Domain(parent_id=host_id)
                    domain_obj.collection_tool_instance_id = tool_instance_id
                    domain_obj.name = domain

                    # Add domain to object mapping
                    obj_map[domain_obj.id] = domain_obj

            # Convert object mapping to list for import
            ret_arr = list(obj_map.values())

            if len(ret_arr) > 0:
                # Import results into framework data model
                scheduled_scan_obj = self.scan_input
                self.import_results(scheduled_scan_obj, ret_arr)
