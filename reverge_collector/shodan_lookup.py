"""
reverge_collector Shodan Lookup Module

This module integrates Shodan, a search engine for Internet-connected devices,
into the reverge_collector security scanning framework. It provides passive reconnaissance
capabilities by querying Shodan's database for information about hosts, services,
and vulnerabilities.

Shodan is a search engine that lets users discover Internet-connected devices and
their associated services, configurations, and security information. This module
leverages Shodan's API to gather intelligence about target networks and hosts.

The module includes:
- Shodan API integration and rate limiting
- Host and subnet reconnaissance
- DNS resolution through Shodan
- Service and technology fingerprinting
- SSL/TLS certificate analysis
- Web component identification
- direct tool execution for scan workflows

Classes:
    Shodan: Main tool class for Shodan integration
    ShodanScope: Luigi task for preparing scan scope
    ShodanScan: Luigi task for executing Shodan queries
    ImportShodanOutput: Luigi task for importing scan results

Functions:
    shodan_dns_query: Perform DNS queries through Shodan API
    shodan_host_query: Query host information from Shodan
    shodan_subnet_query: Query subnet information from Shodan
    shodan_wrapper: Wrapper function for Shodan API calls
    reduce_subnets: Optimize subnet queries for efficiency
"""

import json
import os
import shodan
import netaddr
import time
import ipaddress
import hashlib
import binascii
import logging
from typing import List, Dict, Set, Optional, Any, Union

from reverge_collector import scan_utils
from reverge_collector import data_model
from datetime import datetime
from urllib.parse import urlsplit, urlunsplit
from reverge_collector.tool_spec import ToolSpec


class Shodan(ToolSpec):

    name = 'shodan'
    description = 'Shodan is a search engine for Internet-connected devices'
    project_url = 'https://www.shodan.io/'
    tags = ['passive', 'port-scan', 'service-detection']
    collector_type = data_model.CollectorType.PASSIVE.value
    scan_order = 3
    args = ''
    input_records = [
        data_model.ServerRecordType.HOST,
        data_model.ServerRecordType.SUBNET,
    ]
    output_records = [
        data_model.ServerRecordType.HTTP_ENDPOINT_DATA,
        data_model.ServerRecordType.HTTP_ENDPOINT,
        data_model.ServerRecordType.LIST_ITEM,
        data_model.ServerRecordType.DOMAIN,
        data_model.ServerRecordType.CERTIFICATE,
        data_model.ServerRecordType.WEB_COMPONENT,
        data_model.ServerRecordType.PORT,
        data_model.ServerRecordType.HOST,
    ]

    def get_output_path(self, scan_input) -> str:
        return get_output_path(scan_input)

    def _run_import(self, scan_input) -> bool:
        # Passive tool: execute_scan is called as part of import
        execute_scan(scan_input)
        return super()._run_import(scan_input)

    def execute_scan(self, scan_input) -> None:
        execute_scan(scan_input)

    def parse_output(self, output_path: str, scan_input) -> list:
        return parse_shodan_output(
            output_path,
            scan_input.current_tool_instance_id,
        )


def _prepare_shodan_scope(scheduled_scan_obj) -> str:
    """Prepare shodan input file; returns path."""
    scan_id = scheduled_scan_obj.id
    tool_name = scheduled_scan_obj.current_tool.name
    dir_path = scan_utils.init_tool_folder(tool_name, 'inputs', scan_id)
    shodan_ip_file = dir_path + os.path.sep + "shodan_ips_" + scan_id

    if os.path.isfile(shodan_ip_file):
        return shodan_ip_file

    scope_obj = scheduled_scan_obj.scan_data
    target_list = []
    subnet_map = scope_obj.subnet_map
    for subnet_id in subnet_map:
        subnet_obj = subnet_map[subnet_id]
        subnet_str = "%s/%s" % (subnet_obj.subnet, subnet_obj.mask)
        target_list.append(subnet_str)

    host_list = scope_obj.get_hosts(
        [data_model.RecordTag.SCOPE.value, data_model.RecordTag.LOCAL.value])
    for host_obj in host_list:
        host_str = "%s/32" % (host_obj.ipv4_addr)
        target_list.append(host_str)

    logging.getLogger(__name__).debug(
        "[+] Retrieved %d subnets from database" % len(target_list))
    input_data = {'host_list': target_list}
    with open(shodan_ip_file, 'w') as shodan_fd:
        shodan_fd.write(json.dumps(input_data))

    return shodan_ip_file


def get_output_path(scan_input) -> str:
    scan_id = scan_input.id
    tool_name = scan_input.current_tool.name
    dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)
    return dir_path + os.path.sep + "shodan_out_" + scan_id


def execute_scan(scan_input) -> None:
    output_file_path = get_output_path(scan_input)
    if os.path.exists(output_file_path):
        logging.getLogger(__name__).debug(
            "Output path %s already exists, skipping Shodan scan execution", output_file_path)
        return

    scheduled_scan_obj = scan_input
    shodan_ip_file = _prepare_shodan_scope(scheduled_scan_obj)

    with open(shodan_ip_file) as file_fd:
        input_data = json.loads(file_fd.read())

    shodan_key = scheduled_scan_obj.current_tool_api_key
    if not shodan_key or len(shodan_key) == 0:
        logging.getLogger(__name__).error("No shodan API key provided.")
        raise Exception("No shodan API key provided")

    output_arr = []
    result = shodan_wrapper(shodan_key, '8.8.8.8', 32)
    if result is not None:
        ip_subnets = input_data['host_list']
        logging.getLogger(__name__).debug(
            "Consolidating subnets queried by Shodan")
        if len(ip_subnets) > 50:
            ip_subnets = reduce_subnets(ip_subnets)

        futures = []
        for subnet in ip_subnets:
            subnet = str(subnet)
            subnet_arr = subnet.split("/")
            ip = subnet_arr[0].strip()
            cidr = 32
            if len(subnet_arr) > 1:
                cidr = int(subnet_arr[1])
            ip_network = ipaddress.ip_network(str(ip) + "/" + str(cidr))
            if ip_network.is_private:
                continue
            futures.append(scan_utils.executor.submit(
                shodan_wrapper, shodan_key=shodan_key, ip=ip, cidr=cidr))

        scan_proc_inst = data_model.ToolExecutor(futures)
        scheduled_scan_obj.register_tool_executor(
            scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

        for future in futures:
            result = future.result()
            output_arr.extend(result)

    output_data = {"data": output_arr}
    with open(output_file_path, 'w') as f:
        f.write(json.dumps(output_data))


def shodan_dns_query(api: shodan.Shodan, domain: str) -> List[str]:
    """
    Perform DNS queries through Shodan API to resolve domain to IP addresses.

    This function queries Shodan's DNS database to obtain IP address information
    for a given domain. It handles API rate limiting and error conditions gracefully.

    Args:
        api (shodan.Shodan): Initialized Shodan API client
        domain (str): Domain name to resolve

    Returns:
        List[str]: List of unique IP addresses associated with the domain

    Example:
        >>> api = shodan.Shodan("api_key")
        >>> ips = shodan_dns_query(api, "example.com")
        >>> print(ips)  # ['192.168.1.1', '10.0.0.1']

    Note:
        - Handles rate limiting by sleeping and retrying
        - Filters for A and AAAA record types
        - Returns empty list if no information is available
        - Raises APIError for invalid API keys
    """

    info = None
    while True:
        try:
            info = api.dns.domain_info(domain, history=False, type="A")
            break
        except shodan.exception.APIError as e:
            err_msg = str(e).lower()

            if "limit reached" in err_msg:
                time.sleep(1)
                continue
            if "invalid api key" in err_msg or 'access denied' in err_msg:
                raise e
            if "no information" not in err_msg:
                logging.getLogger(__name__).error(
                    "Shodan API Error DNS: %s" % err_msg)
            break

    # Grab the host information for any IP records that were returned
    results = []
    if info:
        ip_arr = [record['value']
                  for record in info['data'] if record['type'] in ['A', 'AAAA']]
        ip_set = set(ip_arr)
        results = list(ip_set)

    return results


def shodan_host_query(api: shodan.Shodan, ip: Union[str, netaddr.IPAddress]) -> List[Dict[str, Any]]:
    """
    Query Shodan API for detailed host information.

    This function retrieves comprehensive information about a specific IP address
    from Shodan's database, including services, banners, certificates, and
    vulnerability information.

    Args:
        api (shodan.Shodan): Initialized Shodan API client
        ip (Union[str, netaddr.IPAddress]): IP address to query

    Returns:
        List[Dict[str, Any]]: List of service dictionaries containing detailed host data
                             Each service includes port, protocol, banner, and metadata

    Example:
        >>> api = shodan.Shodan("api_key")
        >>> services = shodan_host_query(api, "192.168.1.1")
        >>> for service in services:
        ...     print(f"Port {service['port']}: {service.get('product', 'Unknown')}")

    Note:
        - Handles rate limiting by sleeping and retrying
        - Returns empty list if no information is available
        - Raises APIError for invalid API keys
        - Service data includes ports, protocols, banners, and certificates
    """

    # logging.getLogger(__name__).error("Shodan Host Query: %s" % ip)
    service_list = []
    while True:
        try:
            results = api.host(str(ip))
            if 'data' in results:
                service_list = results['data']
            break
        except shodan.exception.APIError as e:
            err_msg = str(e).lower()
            if "limit reached" in err_msg:
                time.sleep(1)
                continue
            if "invalid api key" in err_msg or 'access denied' in err_msg:
                raise e
            if "no information" not in err_msg:
                logging.getLogger(__name__).error(
                    "Shodan API Error Host: %s" % err_msg)
            break

    return service_list


def shodan_subnet_query(api: shodan.Shodan, subnet: Union[str, netaddr.IPAddress],
                        cidr: int) -> List[Dict[str, Any]]:
    """
    Query Shodan API for information about hosts within a subnet.

    This function searches Shodan's database for all hosts within a specified
    subnet using the net: search filter. It returns service information for
    all discovered hosts in the network range.

    Args:
        api (shodan.Shodan): Initialized Shodan API client
        subnet (Union[str, netaddr.IPAddress]): Network address of the subnet
        cidr (int): CIDR notation prefix length (e.g., 24 for /24)

    Returns:
        List[Dict[str, Any]]: List of service dictionaries for all hosts in subnet
                             Each service includes IP, port, protocol, and metadata

    Example:
        >>> api = shodan.Shodan("api_key")
        >>> services = shodan_subnet_query(api, "192.168.1.0", 24)
        >>> print(f"Found {len(services)} services in subnet")
        >>> for service in services[:5]:  # Show first 5
        ...     print(f"{service['ip_str']}:{service['port']}")

    Note:
        - Uses Shodan's net: search filter for subnet queries
        - Handles rate limiting by sleeping and retrying
        - Returns empty list if no hosts are found in the subnet
        - More efficient than individual host queries for large subnets
    """

    # Query the subnet
    query = "net:%s/%s" % (str(subnet), str(cidr))

    # Loop through the matches and print each IP
    service_list = []
    while True:
        try:
            for service in api.search_cursor(query):
                service_list.append(service)
            break
        except shodan.exception.APIError as e:
            err_msg = str(e).lower()

            if "limit reached" in err_msg:
                time.sleep(1)
                continue
            if "invalid api key" in err_msg or 'access denied' in err_msg:
                raise e
            if "no information" not in err_msg:
                logging.getLogger(__name__).error(
                    "[-] Shodan API Error Subnet: %s" % err_msg)
            break

    return service_list


def shodan_wrapper(shodan_key: str, ip: Optional[str] = None,
                   cidr: Optional[int] = None, domain: Optional[str] = None) -> List[Any]:
    """
    Unified wrapper function for Shodan API queries.

    This function provides a unified interface for different types of Shodan queries,
    handling IP addresses, subnets, and domain names. It automatically selects the
    appropriate query method based on the provided parameters.

    Args:
        shodan_key (str): Shodan API key for authentication
        ip (Optional[str]): IP address to query (used with cidr for subnet queries)
        cidr (Optional[int]): CIDR prefix length for subnet queries
        domain (Optional[str]): Domain name to resolve through Shodan DNS

    Returns:
        List[Any]: Query results - format depends on query type:
                  - Host queries: List of service dictionaries
                  - Subnet queries: List of service dictionaries for all hosts
                  - DNS queries: List of IP addresses

    Example:
        >>> # Host query
        >>> services = shodan_wrapper("api_key", ip="8.8.8.8", cidr=32)
        >>> # Subnet query  
        >>> services = shodan_wrapper("api_key", ip="192.168.1.0", cidr=24)
        >>> # DNS query
        >>> ips = shodan_wrapper("api_key", domain="example.com")

    Note:
        - For /28 and smaller subnets, uses individual host queries
        - For larger subnets, uses subnet search for efficiency
        - Handles all Shodan API authentication and error handling
    """

    results = []
    # Setup the api
    api = shodan.Shodan(shodan_key)
    if ip and cidr:
        if cidr > 28:
            subnet = netaddr.IPNetwork(str(ip)+"/"+str(cidr))
            for ip in subnet.iter_hosts():
                results.extend(shodan_host_query(api, ip))
        else:
            results = shodan_subnet_query(api, ip, cidr)
    elif domain:
        results = shodan_dns_query(api, domain)

    return results


def reduce_subnets(ip_subnets: List[str]) -> List[netaddr.IPNetwork]:
    """
    Optimize subnet list by consolidating and filtering for efficient Shodan queries.

    This function takes a list of IP subnets and optimizes them for Shodan queries by:
    - Converting individual IPs to /24 networks for broader coverage
    - Filtering out private IP ranges (not indexed by Shodan)
    - Merging overlapping subnets to reduce API calls
    - Consolidating adjacent networks where possible

    Args:
        ip_subnets (List[str]): List of IP addresses and subnets in CIDR notation

    Returns:
        List[netaddr.IPNetwork]: Optimized list of network objects for Shodan queries

    Example:
        >>> subnets = ["192.168.1.1/32", "192.168.1.2/32", "10.0.0.0/24"]
        >>> optimized = reduce_subnets(subnets)
        >>> for net in optimized:
        ...     print(net)  # Only public networks, merged where possible

    Note:
        - Expands host IPs (/32) to /24 networks for broader discovery
        - Filters out private IP ranges (RFC 1918, etc.)
        - Uses netaddr.cidr_merge() for intelligent subnet consolidation
        - Reduces API calls by combining adjacent or overlapping ranges
    """

    # Get results for the whole class C
    ret_list = []
    i = 24

    subnet_list = []
    for subnet in ip_subnets:
        # Add class C networks for all IPs
        net_inst = netaddr.IPNetwork(subnet.strip())

        # Skip private IPs
        ip_network = ipaddress.ip_network(subnet.strip())
        if ip_network.is_private:
            continue

        net_ip = str(net_inst.network)

        if net_inst.prefixlen < i:
            network = netaddr.IPNetwork(net_ip + "/%d" % i)
            c_network = network.cidr
            subnet_list.append(c_network)
        else:
            subnet_list.append(net_inst)

    # Merge subnets
    ret_list = netaddr.cidr_merge(subnet_list)

    return ret_list


def parse_shodan_output(
    output_file: str,
    tool_instance_id: Optional[str] = None,
) -> List[Any]:
    """Parse a Shodan JSON output file and return data_model Record objects."""

    with open(output_file, 'r') as file_fd:
        data = file_fd.read()

    ret_arr: List[Any] = []
    path_hash_map: Dict[str, Any] = {}
    hash_alg = hashlib.sha1

    if len(data) > 0:
        json_data = json.loads(data)
        if json_data and len(json_data) > 0:
            scan_data = json_data['data']

            for service in scan_data:
                host_id = None
                port_id = None
                web_path_id = None

                ip_int = service['ip']
                if host_id is None:
                    ip_object = netaddr.IPAddress(ip_int)

                    host_obj = data_model.Host(id=host_id)
                    host_obj.collection_tool_instance_id = tool_instance_id

                    if ip_object.version == 4:
                        host_obj.ipv4_addr = str(ip_object)
                    elif ip_object.version == 6:
                        host_obj.ipv6_addr = str(ip_object)
                    host_id = host_obj.id

                    ret_arr.append(host_obj)

                port = service['port']
                port_obj = data_model.Port(parent_id=host_id)
                port_obj.collection_tool_instance_id = tool_instance_id
                port_obj.proto = 0
                port_obj.port = port
                port_id = port_obj.id

                ret_arr.append(port_obj)

                if 'ssl' in service:
                    port_obj.secure = True

                    ssl = service['ssl']
                    if 'cert' in ssl:
                        cert = ssl['cert']
                        if 'subject' in cert:
                            subject = cert['subject']
                            if 'CN' in subject:
                                domain_str = subject['CN'].lower()

                                domain_obj = data_model.Domain(
                                    parent_id=host_id)
                                domain_obj.collection_tool_instance_id = tool_instance_id
                                domain_obj.name = domain_str

                                ret_arr.append(domain_obj)

                if 'http' in service:
                    http_dict = service['http']

                    endpoint_domain_id = None
                    status_code = None
                    title = None
                    favicon_hash = None
                    tmp_fav_hash = None

                    if 'status' in http_dict:
                        status_code = http_dict['status']

                    if 'title' in http_dict:
                        title = http_dict['title']

                    if 'server' in http_dict:
                        server_str = http_dict['server']
                        if server_str:
                            server = server_str.strip().lower()
                            if len(server) > 0:
                                if " " in server:
                                    server_tech = server.split(" ")[0]
                                else:
                                    server_tech = server

                                server_version = None
                                if "/" in server_tech:
                                    server_tech_arr = server_tech.split("/")
                                    server_tech = server_tech_arr[0]
                                    temp_val = server_tech_arr[-1].strip()
                                    if len(temp_val) > 0:
                                        server_version = temp_val

                                    component_obj = data_model.WebComponent(
                                        parent_id=port_id)
                                    component_obj.collection_tool_instance_id = tool_instance_id
                                    component_obj.name = server_tech

                                    if server_version:
                                        component_obj.version = server_version

                                    ret_arr.append(component_obj)

                    if 'favicon' in http_dict:
                        favicon_dict = http_dict['favicon']
                        tmp_fav_hash = favicon_dict['hash']

                    if 'components' in http_dict:
                        components_dict = http_dict['components']
                        for component_name in components_dict:
                            components_dict_obj = components_dict[component_name]
                            component_name = component_name.lower()

                            component_obj = data_model.WebComponent(
                                parent_id=port_id)
                            component_obj.collection_tool_instance_id = tool_instance_id
                            component_obj.name = component_name

                            if 'versions' in components_dict_obj:
                                version_arr = components_dict_obj['versions']
                                if len(version_arr) > 0:
                                    component_obj.version = version_arr[0]

                            ret_arr.append(component_obj)

                    if 'ssl' in service:
                        port_obj.secure = True

                        ssl = service['ssl']
                        if 'cert' in ssl:
                            cert = ssl['cert']

                            cert_obj = data_model.Certificate(
                                parent_id=port_obj.id)
                            cert_obj.collection_tool_instance_id = tool_instance_id

                            if 'issued' in cert:
                                issued = cert['issued']
                                dt = datetime.strptime(issued, '%Y%m%d%H%M%SZ')
                                cert_obj.issued = int(
                                    time.mktime(dt.timetuple()))

                            if 'expires' in cert:
                                expires = cert['expires']
                                dt = datetime.strptime(
                                    expires, '%Y%m%d%H%M%SZ')
                                cert_obj.expires = int(
                                    time.mktime(dt.timetuple()))

                            if 'fingerprint' in cert:
                                cert_hash_map = cert['fingerprint']
                                if 'sha1' in cert_hash_map:
                                    sha_cert_hash = cert_hash_map['sha1']
                                    cert_obj.fingerprint_hash = sha_cert_hash

                            if 'subject' in cert:
                                subject = cert['subject']
                                if 'CN' in subject:
                                    domain_str = subject['CN'].lower()

                                    domain_obj = cert_obj.add_domain(
                                        host_id, domain_str, tool_instance_id)
                                    if domain_obj:
                                        ret_arr.append(domain_obj)
                                        endpoint_domain_id = domain_obj.id

                            ret_arr.append(cert_obj)

                    hostname_arr = service['hostnames']
                    for domain_name in hostname_arr:
                        if len(domain_name) > 0:
                            domain_name = domain_name.lower()

                            domain_obj = data_model.Domain(parent_id=host_id)
                            domain_obj.collection_tool_instance_id = tool_instance_id
                            domain_obj.name = domain_name

                            ret_arr.append(domain_obj)

                    if 'location' in http_dict:
                        path_location = http_dict['location']
                        if path_location and len(path_location) > 0:
                            split_url = urlsplit(path_location)
                            trimmed_url = split_url._replace(query='')
                            trimmed_path = urlunsplit(trimmed_url)
                            if tmp_fav_hash and trimmed_path == "/":
                                favicon_hash = tmp_fav_hash

                            hashobj = hash_alg()
                            hashobj.update(trimmed_path.encode())
                            path_hash = hashobj.digest()
                            hex_str = binascii.hexlify(path_hash).decode()
                            web_path_hash = hex_str

                            if web_path_hash in path_hash_map:
                                path_obj = path_hash_map[web_path_hash]
                            else:
                                path_obj = data_model.ListItem()
                                path_obj.collection_tool_instance_id = tool_instance_id
                                path_obj.web_path = trimmed_path
                                path_obj.web_path_hash = web_path_hash
                                path_hash_map[web_path_hash] = path_obj
                                ret_arr.append(path_obj)

                            web_path_id = path_obj.id

                    http_endpoint_obj = data_model.HttpEndpoint(
                        parent_id=port_obj.id)
                    http_endpoint_obj.collection_tool_instance_id = tool_instance_id
                    http_endpoint_obj.web_path_id = web_path_id

                    ret_arr.append(http_endpoint_obj)

                    http_endpoint_data_obj = data_model.HttpEndpointData(
                        parent_id=http_endpoint_obj.id)
                    http_endpoint_data_obj.collection_tool_instance_id = tool_instance_id
                    http_endpoint_data_obj.domain_id = endpoint_domain_id
                    http_endpoint_data_obj.title = title
                    http_endpoint_data_obj.status = status_code
                    http_endpoint_data_obj.fav_icon_hash = favicon_hash

                    ret_arr.append(http_endpoint_data_obj)

    return ret_arr
