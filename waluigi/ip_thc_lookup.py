"""
IP THC IP Lookup Module.

This module provides comprehensive passive DNS reconnaissance capabilities using
IP THC, a threat-intelligence platform specializing in DNS and domain data.
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
    IPThc: Main tool class implementing the IP THC API interface
    IPThcIPLookupScan: Luigi task for executing IP lookup operations
    ImportIPThcIPLookupOutput: Luigi task for importing and processing lookup results

Functions:
    request_wrapper: Core API request function for IP THC IP lookup

Global Variables:
    proxies: HTTP proxy configuration for API requests

Example:
    Basic usage through the Waluigi framework::
    
        # Initialize the tool
        ip_thc = IPThc()
        
        # Execute IP lookup
        success = ip_thc.import_func(scan_input_obj)

Note:
    This module performs passive reconnaissance and does not generate network traffic
    to target systems. The tool provides historical and current DNS data
    for comprehensive domain intelligence gathering.

"""

import http.client
import luigi
import os
import json
import logging
import netaddr
from typing import Dict, Set, List, Any, Optional, Union

from luigi.util import inherits
from waluigi import scan_utils
from waluigi import data_model

# Global proxy configuration for IP THC API requests
proxies: Optional[Dict[str, str]] = None


class IPThc(data_model.WaluigiTool):
    """
    IP THC threat intelligence platform integration for the Waluigi framework.

    This class provides integration with IP THC, a comprehensive threat-intelligence
    platform specializing in DNS and domain data collection. It implements the WaluigiTool
    interface to provide passive DNS reconnaissance capabilities within the security
    reconnaissance workflow.

    IP THC offers extensive capabilities including:
        - Current and historical DNS record collection
        - Passive DNS data for comprehensive domain analysis
        - WHOIS information and domain registration data
        - IP-to-domain resolution with historical context
        - Subdomain discovery and enumeration
        - DNS infrastructure analysis and mapping

    Attributes:
        name (str): The tool identifier ('ipthc')
        description (str): Human-readable description of the platform's capabilities
        project_url (str): URL to the official IP THC website
        collector_type (int): Identifies this as a passive reconnaissance tool
        scan_order (int): Execution priority within the reconnaissance workflow (5)
        args (str): Command-line arguments (empty for API-based tools)
        import_func (callable): Static method for importing lookup results

    Methods:
        import_ip_thc_ip_lookup: Imports and processes IP THC lookup results

    Example:
        >>> tool = IPThc()
        >>> print(tool.name)
        ip_thc

        >>> # Execute IP lookup through the framework (requires API key)
        >>> success = tool.import_func(scan_input_obj)
        >>> if success:
        ...     print("IP THC lookup completed successfully")

    Note:
        The scan_order of 5 positions this tool early in the reconnaissance workflow
        to provide domain intelligence for subsequent active scanning phases.
        Requires a valid IP THC API key for operation.
    """

    def __init__(self) -> None:
        """
        Initialize the IP THC tool with default configuration.

        Sets up the tool with appropriate parameters for passive DNS reconnaissance,
        including API integration points and workflow positioning for optimal
        intelligence gathering sequence.
        """
        self.name = 'ipthc'
        self.description = 'IP THC is a threat-intelligence platform specializing in DNS and domain data. It continuously collects both current and historical DNS records, WHOIS information, and passive-DNS data to give users a comprehensive view of any domain\'s evolution over time'
        self.project_url = 'https://ip.thc.org/'
        self.collector_type = data_model.CollectorType.PASSIVE.value
        self.scan_order = 5
        self.args = ""
        self.import_func = IPThc.import_ip_thc_ip_lookup
        self.input_records = [data_model.ServerRecordType.HOST,
                              data_model.ServerRecordType.SUBNET, data_model.ServerRecordType.DOMAIN]
        self.output_records = [data_model.ServerRecordType.DOMAIN]

    @staticmethod
    def import_ip_thc_ip_lookup(scan_input: data_model.ScheduledScan) -> bool:
        """
        Import and process IP THC IP lookup results.

        This static method serves as the main entry point for executing IP THC
        IP-to-domain lookups within the Waluigi framework. It creates and executes
        a Luigi workflow to perform the API-based reconnaissance and import results
        into the framework's data model.

        Args:
            scan_input (data_model.ScheduledScan): The scheduled scan object containing
                target information, API keys, and framework configuration needed
                for the IP THC lookup operation.

        Returns:
            bool: True if the lookup and import operation completed successfully,
                  False if any errors occurred during execution.

        Example:
            >>> scan_obj = data_model.ScheduledScan(...)
            >>> success = IPThc.import_ip_thc_ip_lookup(scan_obj)
            >>> if success:
            ...     print("IP THC lookup completed")

        Note:
            The operation is performed asynchronously using Luigi's task execution framework.
        """
        luigi_run_result = luigi.build([ImportIPThcIPLookupOutput(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


def request_wrapper(ip_addr: str) -> Dict[str, Union[str, List[str]]]:
    """
    Execute IP THC API request for IP-to-domain lookup.

    This function performs the core API communication with IP THC to resolve
    an IP address to associated domain names. It handles response parsing to
    extract domain information from the API response.

    The function queries IP THC's lookup endpoint with the provided IP address
    and returns all associated domain names found in their passive DNS database.

    Args:
        ip_addr (str): The IPv4 address or CIDR range to lookup in IP THC database.
            Must be a valid IPv4 address format (e.g., '192.168.1.1').

    Returns:
        Dict[str, Union[str, List[str]]]: Dictionary containing lookup results with keys:
            - 'ip_addr' (str): The original IP address that was queried
            - 'domains' (List[str]): List of unique domain names associated with the IP

    Raises:
        RuntimeError: If the API request fails with non-recoverable error codes
            or if the IP THC service returns invalid responses.

    Example:
        >>> result = request_wrapper('8.8.8.8')
        >>> print(f"Found {len(result['domains'])} domains for {result['ip_addr']}")
        Found 5 domains for 8.8.8.8

        >>> for domain in result['domains']:
        ...     print(f"  - {domain}")

    Note:
        The function uses http.client for direct HTTPS communication with IP THC.
        IP THC returns domain information with metadata like apex_domain, country, etc.
        This function extracts unique domain names from the response.
    """
    # Initialize domain set for collecting unique domains
    domain_set: Set[str] = set()
    ret_str: Dict[str, Union[str, List[str]]] = {'ip_addr': ip_addr}

    # Prepare payload for IP THC API request
    payload = json.dumps({
        "ip_address": ip_addr
    })

    # Set up API headers
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    # Execute API request
    try:
        conn = http.client.HTTPSConnection("ip.thc.org")
        conn.request("POST", "/api/v1/lookup", payload, headers)
        res = conn.getresponse()
        data = res.read()

        # Check response status
        if res.status != 200:
            logging.getLogger(__name__).debug(
                "Status code: %d" % res.status)
            logging.getLogger(__name__).debug(data.decode("utf-8"))
            raise RuntimeError("[-] Error getting IP THC output.")

        # Parse API response and extract domain information
        content = json.loads(data.decode("utf-8"))

        # IP THC returns response with 'domains' key containing array of domain objects
        if isinstance(content, dict) and 'domains' in content:
            domains_array = content['domains']
            if isinstance(domains_array, list):
                # Each domain object contains domain name and metadata
                for domain_obj in domains_array:
                    if isinstance(domain_obj, dict):
                        # Extract the domain name from the domain object
                        if 'domain' in domain_obj:
                            domain_name = domain_obj['domain'].strip()
                            if domain_name:
                                domain_set.add(domain_name)
                    elif isinstance(domain_obj, str):
                        # Handle case where domain is just a string
                        domain_obj = domain_obj.strip()
                        if domain_obj:
                            domain_set.add(domain_obj)

        conn.close()
    except Exception as e:
        logging.getLogger(__name__).error(
            f"Error during IP THC lookup: {str(e)}")
        raise RuntimeError(f"[-] Error getting IP THC output: {str(e)}")

    # Return results with unique domains sorted for consistency
    ret_str['domains'] = sorted(list(domain_set))
    return ret_str


class IPThcIPLookupScan(luigi.Task):
    """
    Luigi task for executing IP THC IP lookup operations.

    This task handles the execution of IP THC API requests for IP-to-domain
    lookups within the Luigi workflow framework. It processes multiple IP addresses
    from the scan input, performs concurrent API requests, and saves results to
    the output file for subsequent import processing.

    The task supports:
        - Concurrent API requests for multiple IP addresses
        - Error handling for API calls
        - Progress tracking and execution monitoring
        - Structured output generation for import processing

    Attributes:
        scan_input (luigi.Parameter): The scheduled scan object containing target
            IP addresses.

    Methods:
        output: Defines the output file path for lookup results
        run: Executes the IP lookup operation and saves results

    Example:
        >>> # Task is typically executed through Luigi framework
        >>> task = IPThcIPLookupScan(scan_input=scan_obj)
        >>> luigi.build([task], local_scheduler=True)

    Note:
        Results are saved in JSON format for import processing.
    """

    # Luigi task parameter for scan input configuration
    scan_input = luigi.Parameter()

    def output(self) -> luigi.LocalTarget:
        """
        Define the output file path for IP THC lookup results.

        Creates the necessary directory structure and defines the output file
        path where IP lookup results will be stored in JSON format.

        Returns:
            luigi.LocalTarget: Target object representing the output file path
                for storing IP THC lookup results.

        Example:
            >>> task = IPThcIPLookupScan(scan_input=scan_obj)
            >>> output_target = task.output()
            >>> print(output_target.path)
            /path/to/outputs/ip-thc-ip-lookup-outputs-scan123
        """

        scheduled_scan_obj = self.scan_input
        scan_id = scheduled_scan_obj.id

        # Initialize output directory structure
        tool_name = scheduled_scan_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)

        # Define output file path
        http_outputs_file = dir_path + os.path.sep + \
            "ip-thc-ip-lookup-outputs-" + scan_id
        return luigi.LocalTarget(http_outputs_file)

    def run(self) -> None:
        """
        Execute IP THC IP lookup operations for all target IP addresses and subnets.

        This method performs the main execution logic for the IP THC lookup
        task. It processes all IP addresses and subnets from the scan input, executes concurrent
        API requests, and saves the results to the output file.

        For IP addresses with existing Host objects, domains are mapped to those hosts.
        For subnets, domains are queried and IPs are extracted from domain names where possible.
        Host objects are created for any discovered IPs within the subnet range.

        The execution process includes:
            - Processing target IP addresses and subnets from scan input
            - Executing concurrent API requests with thread pool
            - Collecting and organizing lookup results
            - Extracting IPs from domain names for subnet results
            - Creating Host objects for discovered subnet IPs
            - Saving results to output file in JSON format

        Raises:
            Exception: If no target map is available in the scan input configuration.

        Example:
            >>> task = IPThcIPLookupScan(scan_input=scan_obj)
            >>> task.run()  # Executes the lookup operation

        Note:
            This method uses a thread pool executor for concurrent API requests
            to improve performance when processing multiple IP addresses and subnets.
        """

        scheduled_scan_obj = self.scan_input

        # Get output file path for results storage
        output_file_path = self.output().path

        # Initialize IP-to-host mapping dictionary
        ip_to_host_dict_map: Dict[str, Dict[str, Any]] = {}

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

            # Add IP address to host mapping with existing host ID
            ip_to_host_dict_map[ip_addr] = {
                'host_id': host_obj.id,
                'is_subnet': False,
                'subnet_obj': None
            }

        target_list = []
        subnet_map = scheduled_scan_obj.scan_data.subnet_map
        for subnet_id in subnet_map:
            subnet_obj = subnet_map[subnet_id]
            if int(subnet_obj.mask) < 25:
                # Large subnets: query as CIDR range, extract IPs from domain names
                subnet_str = "%s/%s" % (subnet_obj.subnet, subnet_obj.mask)
                target_list.append(subnet_str)
                ip_to_host_dict_map[subnet_str] = {
                    'host_id': None,
                    'is_subnet': True,
                    'subnet_obj': subnet_obj
                }
            else:
                # Small subnets: expand into individual IP addresses
                ip_list = scan_utils.expand_cidr(
                    subnet_obj.subnet, subnet_obj.mask)
                for ip_addr in ip_list:
                    target_list.append(ip_addr)

                    # Add IP address to host mapping if not already present
                    if ip_addr not in ip_to_host_dict_map:
                        ip_to_host_dict_map[ip_addr] = {
                            'host_id': None,
                            'is_subnet': False,
                            'subnet_obj': None
                        }

        # Execute concurrent API requests for all IP addresses and subnets
        futures = []
        for ip_addr in ip_to_host_dict_map:
            futures.append(scan_utils.executor.submit(
                request_wrapper, ip_addr=ip_addr))

        # Register futures with scan execution framework
        scan_proc_inst = data_model.ToolExecutor(futures)
        scheduled_scan_obj.register_tool_executor(
            scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

        # Collect results from concurrent API requests
        serializable_map = {}
        for future in futures:
            ret_dict = future.result()
            # Extract IP address/subnet from results
            ip_or_subnet = ret_dict['ip_addr']
            # Get corresponding mapping dictionary
            target_dict = ip_to_host_dict_map[ip_or_subnet]

            # For subnets, resolve domains to IPs and create host entries
            ret_domains = ret_dict['domains']
            if ret_domains and len(ret_domains) > 0:

                if target_dict['is_subnet']:
                    subnet_obj = target_dict['subnet_obj']
                    subnet_network = netaddr.IPNetwork(
                        "%s/%s" % (subnet_obj.subnet, subnet_obj.mask))

                    # Resolve domains to IPs and create host entries using scan_utils.dns_wrapper
                    dns_results = scan_utils.dns_wrapper(
                        set(ret_domains))
                    for dns_result in dns_results:
                        domain = dns_result['domain']
                        resolved_ip = dns_result['ip']
                        try:
                            ip_obj = netaddr.IPAddress(resolved_ip)
                            # Check if resolved IP is within the subnet range
                            if ip_obj in subnet_network:
                                ip_str = str(ip_obj)
                                # Create new host entry for this IP if not already present
                                if ip_str not in serializable_map:
                                    serializable_map[ip_str] = {
                                        'host_id': None,
                                        'domains': [domain],
                                    }
                                elif 'domains' not in serializable_map[ip_str]:
                                    serializable_map[ip_str]['domains'] = [
                                        domain]
                                else:
                                    if domain not in serializable_map[ip_str]['domains']:
                                        serializable_map[ip_str]['domains'].append(
                                            domain)
                        except (netaddr.core.AddrFormatError, ValueError):
                            # Skip invalid IP addresses
                            pass
                else:

                    if ip_or_subnet not in serializable_map:
                        serializable_map[ip_or_subnet] = {
                            'host_id': target_dict['host_id'],
                            'domains': ret_domains,
                        }
                    elif 'domains' not in serializable_map[ip_or_subnet]:
                        serializable_map[ip_or_subnet]['domains'] = ret_domains
                    else:
                        serializable_map[ip_or_subnet]['domains'].extend(
                            ret_domains)

        results_dict = {'ip_to_host_dict_map': serializable_map}

        # Write results to output file in JSON format
        with open(output_file_path, 'w') as file_fd:
            file_fd.write(json.dumps(results_dict))


@inherits(IPThcIPLookupScan)
class ImportIPThcIPLookupOutput(data_model.ImportToolXOutput):
    """
    Luigi task for importing and processing IP THC IP lookup results.

    This task handles the import and integration of IP THC lookup results
    into the Waluigi framework's data model. It reads the JSON output from the
    lookup scan, processes domain information, and creates appropriate data model
    objects for storage in the framework database.

    The import process includes:
        - Reading JSON output from IP THC lookup scan
        - Processing IP-to-domain mappings from API results
        - Creating Domain objects with proper parent relationships
        - Integrating results into the framework's data model
        - Updating scan progress and status information

    Attributes:
        Inherits all attributes from IPThcIPLookupScan and ImportToolXOutput

    Methods:
        requires: Specifies dependency on IPThcIPLookupScan task
        run: Processes lookup results and imports into data model

    Example:
        >>> # Task is executed as part of the Luigi workflow
        >>> import_task = ImportIPThcIPLookupOutput(scan_input=scan_obj)
        >>> luigi.build([import_task], local_scheduler=True)

    Note:
        This task creates Domain objects with collection_tool_instance_id
        for tracking which tool instance discovered each domain.
    """

    def requires(self) -> IPThcIPLookupScan:
        """
        Specify task dependencies for the import operation.

        Returns:
            IPThcIPLookupScan: The lookup scan task that must complete
                before this import task can execute.
        """
        return IPThcIPLookupScan(scan_input=self.scan_input)

    def run(self) -> None:
        """
        Import and process IP THC IP lookup results into the data model.

        This method reads the JSON output from the IP THC lookup scan,
        processes the IP-to-domain mappings, creates Domain objects for each
        discovered domain, and imports them into the framework's data model.

        For IPs with existing Host objects (from original scope), Domain objects
        are created with the existing host as parent.

        For IPs discovered from subnet queries (extracted from domain names),
        new Host objects are created before Domain objects are attached.

        The import process includes:
            - Reading lookup results from the output file
            - Parsing IP-to-host-to-domain mappings
            - Creating Host objects for IPs discovered from subnet queries
            - Creating Domain objects with proper parent-child relationships
            - Setting collection tool instance IDs for tracking
            - Importing results into the framework database

        Example:
            >>> import_task = ImportIPThcIPLookupOutput(scan_input=scan_obj)
            >>> import_task.run()  # Processes and imports results

        Note:
            Domain objects are created with parent_id linking to the host object
            and collection_tool_instance_id for tracking discovery source.
            Host objects are created for IPs discovered during subnet queries.
        """

        scheduled_scan_obj = self.scan_input
        tool_instance_id = scheduled_scan_obj.current_tool_instance_id

        # Read lookup results from output file
        scan_output_file = self.input().path
        with open(scan_output_file, 'r') as file_fd:
            data = file_fd.read()

        # Initialize object lists for results
        host_obj_map: Dict[str, data_model.Host] = {}
        domain_obj_list: List[data_model.Domain] = []

        if len(data) > 0:
            # Parse JSON results from lookup scan
            scan_data_dict = json.loads(data)

            # Process IP-to-host-to-domain mappings
            ip_to_host_dict_map = scan_data_dict['ip_to_host_dict_map']

            # First pass: create Host objects for IPs discovered from subnet queries
            for ip_addr in ip_to_host_dict_map:
                target_dict = ip_to_host_dict_map[ip_addr]

                # Check if this IP was discovered from a subnet query
                if target_dict['host_id'] is None:
                    # Create new Host object for this discovered IP
                    host_obj = data_model.Host()
                    host_obj.collection_tool_instance_id = tool_instance_id

                    # Determine if IP is IPv4 or IPv6
                    try:
                        ip_obj = netaddr.IPAddress(ip_addr)
                        if ip_obj.version == 4:
                            host_obj.ipv4_addr = ip_addr
                        else:
                            host_obj.ipv6_addr = ip_addr
                    except (netaddr.core.AddrFormatError, ValueError):
                        # Skip invalid IP addresses
                        continue

                    # Store host object for later reference
                    host_obj_map[ip_addr] = host_obj
                    # Update mapping with new host ID
                    target_dict['host_id'] = host_obj.id

            # Second pass: create Domain objects linked to Host objects
            for ip_addr in ip_to_host_dict_map:
                target_dict = ip_to_host_dict_map[ip_addr]
                host_id = target_dict['host_id']
                domains = target_dict.get('domains', [])

                # Create Domain objects for each discovered domain
                for domain in domains:
                    domain_obj = data_model.Domain(parent_id=host_id)
                    domain_obj.collection_tool_instance_id = tool_instance_id
                    domain_obj.name = domain

                    # Add domain to results list
                    domain_obj_list.append(domain_obj)

            # Combine host and domain objects for import
            ret_arr: List[Any] = list(host_obj_map.values()) + domain_obj_list

            if len(ret_arr) > 0:
                # Import results into framework data model
                scheduled_scan_obj = self.scan_input
                self.import_results(scheduled_scan_obj, ret_arr)
