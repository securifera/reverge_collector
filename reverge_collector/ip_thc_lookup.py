
"""
IP THC IP Lookup Module.

This module provides comprehensive passive DNS reconnaissance capabilities using
IP THC, a threat-intelligence platform specializing in DNS and domain data.
It integrates with the reverge_collector framework to perform automated IP-to-domain resolution
and historical DNS data collection for security reconnaissance.

The module supports:
    - Passive DNS reconnaissance for IP addresses
    - Historical domain resolution data collection
    - Current and historical DNS record analysis
    - WHOIS information gathering capabilities
    - Comprehensive domain discovery from IP addresses
    - API-based threat intelligence data collection
    - Integration with the reverge_collector passive reconnaissance workflow

Classes:
    IPThc: Main tool class implementing the IP THC API interface
    IPThcIPLookupScan: Luigi task for executing IP lookup operations
    ImportIPThcIPLookupOutput: Luigi task for importing and processing lookup results

Functions:
    request_wrapper: Core API request function for IP THC IP lookup

Global Variables:
    proxies: HTTP proxy configuration for API requests

Example:
    Basic usage through the reverge_collector framework::

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
import os
import json
import logging
import netaddr
from typing import Dict, Set, List, Any, Optional, Union

from reverge_collector import scan_utils
from reverge_collector import data_model
from reverge_collector.tool_spec import ToolSpec

# Global proxy configuration for IP THC API requests
proxies: Optional[Dict[str, str]] = None


class IPThc(ToolSpec):

    name = 'ipthc'
    description = "IP THC is a threat-intelligence platform specializing in DNS and domain data. It continuously collects both current and historical DNS records, WHOIS information, and passive-DNS data to give users a comprehensive view of any domain's evolution over time"
    project_url = 'https://ip.thc.org/'
    tags = ['passive', 'dns-enum']
    collector_type = data_model.CollectorType.PASSIVE.value
    scan_order = 5
    args = ''
    input_records = [
        data_model.ServerRecordType.HOST,
        data_model.ServerRecordType.SUBNET,
        data_model.ServerRecordType.DOMAIN,
    ]
    output_records = [data_model.ServerRecordType.DOMAIN]

    def get_output_path(self, scan_input) -> str:
        return get_output_path(scan_input)

    def _run_import(self, scan_input) -> bool:
        # Passive tool: execute_scan is called as part of import
        execute_scan(scan_input)
        return super()._run_import(scan_input)

    def execute_scan(self, scan_input) -> None:
        execute_scan(scan_input)

    def parse_output(self, output_path: str, scan_input) -> list:
        return parse_ip_thc_output(
            output_path,
            scan_input.current_tool_instance_id,
        )


def process_response(data):

    domain_set = set()
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

    return domain_set


def subdomain_request_wrapper(domain: str) -> Dict[str, Union[str, List[str]]]:
    """
    Execute IP THC API request for IP-to-domain lookup.

    This function performs the core API communication with IP THC to resolve
    an IP address to associated domain names. It handles response parsing to
    extract domain information from the API response.

    The function queries IP THC's lookup endpoint with the provided IP address
    and returns all associated domain names found in their passive DNS database.

    Args:
        domain (str): The domain to lookup in IP THC database.

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
    ret_str: Dict[str, Union[str, List[str]]] = {
        'target': domain, 'domains': []}

    # Prepare payload for IP THC API request
    payload = json.dumps({
        "domain": domain
    })

    # Set up API headers
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    import time
    data = None
    retry_count = 0
    try:
        while True:
            conn = http.client.HTTPSConnection("ip.thc.org")
            conn.request("POST", "/api/v1/lookup/subdomains", payload, headers)
            res = conn.getresponse()
            data = res.read()
            if res.status == 429:
                backoff = min(2 ** retry_count, 60)
                logging.getLogger(__name__).warning(
                    "Received 429 Too Many Requests. Sleeping %d seconds and retrying. Payload: %s", backoff, payload)
                time.sleep(backoff)
                retry_count += 1
                continue
            if res.status == 406:
                try:
                    decoded_data = data.decode("utf-8")
                except Exception:
                    decoded_data = str(data)
                logging.getLogger(__name__).warning(
                    f"IP THC lookup skipped. Status: 406 Not Acceptable. Payload: {payload}, Response: {decoded_data}")
                return ret_str
            if res.status != 200:
                logging.getLogger(__name__).error(
                    f"IP THC lookup failed. Status code: {res.status}")
                # logging.getLogger(__name__).error(f"Payload sent: {payload}")
                try:
                    decoded_data = data.decode("utf-8")
                except Exception:
                    decoded_data = str(data)
                # logging.getLogger(__name__).error(
                #    f"Response data: {decoded_data}")
                raise RuntimeError(
                    f"[-] Error getting IP THC output. Status: {res.status}, Payload: {payload}, Response: {decoded_data}")
            break
        conn.close()
    except Exception as e:
        logging.getLogger(__name__).error(
            f"Error during IP THC lookup: {str(e)}")
        raise RuntimeError(f"[-] Error getting IP THC output: {str(e)}")

    if data:
        # logging.getLogger(__name__).warning(
        #    "Response Data: %s" % data.decode("utf-8"))
        domain_set = process_response(data)

        # Return results with unique domains sorted for consistency
        ret_str['domains'] = sorted(list(domain_set))

    return ret_str


def reverse_dns_request_wrapper(ip_addr: str) -> Dict[str, Union[str, List[str]]]:
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
    ret_str: Dict[str, Union[str, List[str]]] = {
        'target': ip_addr, 'domains': []}

    # Prepare payload for IP THC API request
    payload = json.dumps({
        "ip_address": ip_addr
    })

    # Set up API headers
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    import time
    data = None
    retry_count = 0
    try:
        while True:
            conn = http.client.HTTPSConnection("ip.thc.org")
            conn.request("POST", "/api/v1/lookup", payload, headers)
            res = conn.getresponse()
            data = res.read()
            if res.status == 429:
                backoff = min(2 ** retry_count, 60)
                logging.getLogger(__name__).warning(
                    "Received 429 Too Many Requests. Sleeping %d seconds and retrying. Payload: %s", backoff, payload)
                time.sleep(backoff)
                retry_count += 1
                continue
            if res.status == 406:
                try:
                    decoded_data = data.decode("utf-8")
                except Exception:
                    decoded_data = str(data)
                logging.getLogger(__name__).warning(
                    f"IP THC lookup skipped. Status: 406 Not Acceptable. Payload: {payload}, Response: {decoded_data}")
                return ret_str
            if res.status != 200:
                logging.getLogger(__name__).error(
                    f"IP THC lookup failed. Status code: {res.status}")
                logging.getLogger(__name__).error(f"Payload sent: {payload}")
                try:
                    decoded_data = data.decode("utf-8")
                except Exception:
                    decoded_data = str(data)
                logging.getLogger(__name__).error(
                    f"Response data: {decoded_data}")
                raise RuntimeError(
                    f"[-] Error getting IP THC output. Status: {res.status}, Payload: {payload}, Response: {decoded_data}")
            break
        conn.close()
    except Exception as e:
        logging.getLogger(__name__).error(
            f"Error during IP THC lookup: {str(e)}")
        raise RuntimeError(f"[-] Error getting IP THC output: {str(e)}")

    if data:
        domain_set = process_response(data)

        # Return results with unique domains sorted for consistency
        ret_str['domains'] = sorted(list(domain_set))

    return ret_str


def get_output_path(scan_input) -> str:
    scan_id = scan_input.id
    tool_name = scan_input.current_tool.name
    dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)
    return dir_path + os.path.sep + "ip-thc-ip-lookup-outputs-" + scan_id


def execute_scan(scan_input) -> None:
    output_file_path = get_output_path(scan_input)
    if os.path.exists(output_file_path):
        return

    scheduled_scan_obj = scan_input
    ip_to_host_dict_map: Dict[str, Dict[str, Any]] = {}

    target_map = scheduled_scan_obj.scan_data.host_port_obj_map
    if len(target_map) == 0:
        logging.getLogger(__name__).debug("No target map in scan input")

    for target_key in target_map:
        target_obj_dict = target_map[target_key]
        host_obj = target_obj_dict['host_obj']
        ip_addr = host_obj.ipv4_addr
        ip_to_host_dict_map[ip_addr] = {
            'host_id': host_obj.id,
            'obj_type': 'ip',
            'obj': None
        }

    target_list = []
    subnet_map = scheduled_scan_obj.scan_data.subnet_map
    for subnet_id in subnet_map:
        subnet_obj = subnet_map[subnet_id]
        if int(subnet_obj.mask) < 25:
            subnet_str = "%s/%s" % (subnet_obj.subnet, subnet_obj.mask)
            target_list.append(subnet_str)
            ip_to_host_dict_map[subnet_str] = {
                'host_id': None,
                'obj_type': 'subnet',
                'obj': subnet_obj
            }
        else:
            ip_network = netaddr.IPNetwork(
                f"{subnet_obj.subnet}/{subnet_obj.mask}")
            for ip_addr in [str(ip) for ip in ip_network]:
                target_list.append(ip_addr)
                if ip_addr not in ip_to_host_dict_map:
                    ip_to_host_dict_map[ip_addr] = {
                        'host_id': None,
                        'obj_type': 'ip',
                        'obj': None
                    }

    futures = []
    for ip_addr in ip_to_host_dict_map:
        futures.append(scan_utils.executor.submit(
            reverse_dns_request_wrapper, ip_addr=ip_addr))

    domain_obj_list = scheduled_scan_obj.scan_data.get_domains(
        [data_model.RecordTag.SCOPE.value, data_model.RecordTag.LOCAL.value])
    for domain_obj in domain_obj_list:
        if scan_utils.is_cloud_domain(domain_obj.name):
            logging.getLogger(__name__).debug(
                "Skipping cloud hosting domain: %s" % domain_obj.name)
            continue
        if domain_obj.name.startswith("*."):
            logging.getLogger(__name__).debug(
                "Skipping wildcard domain: %s" % domain_obj.name)
            continue
        ip_to_host_dict_map[domain_obj.name] = {
            'host_id': None,
            'obj_type': 'domain',
            'obj': domain_obj
        }
        futures.append(scan_utils.executor.submit(
            subdomain_request_wrapper, domain=domain_obj.name))

    scan_proc_inst = data_model.ToolExecutor(futures)
    scheduled_scan_obj.register_tool_executor(
        scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

    serializable_map = {}
    for future in futures:
        ret_dict = future.result()
        ip_or_subnet = ret_dict['target']
        target_dict = ip_to_host_dict_map[ip_or_subnet]
        ret_domains = ret_dict['domains']
        if ret_domains and len(ret_domains) > 0:
            if target_dict['obj_type'] == 'subnet':
                subnet_obj = target_dict['obj']
                subnet_network = netaddr.IPNetwork(
                    "%s/%s" % (subnet_obj.subnet, subnet_obj.mask))
                dns_results = scan_utils.dns_wrapper(set(ret_domains))
                for dns_result in dns_results:
                    domain = dns_result['domain']
                    resolved_ip = dns_result['ip']
                    try:
                        ip_obj = netaddr.IPAddress(resolved_ip)
                        if ip_obj in subnet_network:
                            ip_str = str(ip_obj)
                            if ip_str not in serializable_map:
                                serializable_map[ip_str] = {
                                    'host_id': None, 'domains': [domain]}
                            elif 'domains' not in serializable_map[ip_str]:
                                serializable_map[ip_str]['domains'] = [domain]
                            else:
                                if domain not in serializable_map[ip_str]['domains']:
                                    serializable_map[ip_str]['domains'].append(
                                        domain)
                    except (netaddr.core.AddrFormatError, ValueError):
                        pass
            elif target_dict['obj_type'] == 'domain':
                dns_results = scan_utils.dns_wrapper(set(ret_domains))
                for dns_result in dns_results:
                    domain = dns_result['domain']
                    resolved_ip = dns_result['ip']
                    try:
                        ip_obj = netaddr.IPAddress(resolved_ip)
                        ip_str = str(ip_obj)
                        if ip_str not in serializable_map:
                            serializable_map[ip_str] = {
                                'host_id': None, 'domains': [domain]}
                        elif 'domains' not in serializable_map[ip_str]:
                            serializable_map[ip_str]['domains'] = [domain]
                        else:
                            if domain not in serializable_map[ip_str]['domains']:
                                serializable_map[ip_str]['domains'].append(
                                    domain)
                    except (netaddr.core.AddrFormatError, ValueError):
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
    with open(output_file_path, 'w') as file_fd:
        file_fd.write(json.dumps(results_dict))


def parse_ip_thc_output(
    output_file: str,
    tool_instance_id: Optional[str] = None,
) -> List[Any]:
    """Parse an IP THC JSON output file and return data_model Record objects."""

    with open(output_file, 'r') as file_fd:
        data = file_fd.read()

    host_obj_map: Dict[str, data_model.Host] = {}
    domain_obj_list: List[data_model.Domain] = []

    if len(data) > 0:
        scan_data_dict = json.loads(data)
        ip_to_host_dict_map = scan_data_dict['ip_to_host_dict_map']

        for ip_addr in ip_to_host_dict_map:
            target_dict = ip_to_host_dict_map[ip_addr]

            if target_dict['host_id'] is None:
                host_obj = data_model.Host()
                host_obj.collection_tool_instance_id = tool_instance_id

                try:
                    ip_obj = netaddr.IPAddress(ip_addr)
                    if ip_obj.version == 4:
                        host_obj.ipv4_addr = ip_addr
                    else:
                        host_obj.ipv6_addr = ip_addr
                except (netaddr.core.AddrFormatError, ValueError):
                    continue

                host_obj_map[ip_addr] = host_obj
                target_dict['host_id'] = host_obj.id

        for ip_addr in ip_to_host_dict_map:
            target_dict = ip_to_host_dict_map[ip_addr]
            host_id = target_dict['host_id']
            domains = target_dict.get('domains', [])

            for domain in domains:
                domain_obj = data_model.Domain(parent_id=host_id)
                domain_obj.collection_tool_instance_id = tool_instance_id
                domain_obj.name = domain
                domain_obj_list.append(domain_obj)

    return list(host_obj_map.values()) + domain_obj_list
