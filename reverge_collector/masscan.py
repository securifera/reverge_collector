"""
reverge_collector Masscan Integration Module

This module integrates Masscan, a high-speed port scanner, into the reverge_collector
security scanning framework. Masscan is designed for large-scale network
scanning and can scan the entire Internet in under 6 minutes, transmitting
10 million packets per second.

Masscan is optimized for speed and can handle massive IP ranges efficiently.
It uses its own TCP/IP stack implementation to achieve maximum performance
for network reconnaissance operations.

The module includes:
- Masscan tool integration and configuration
- High-speed port scanning across large network ranges
- XML output parsing and result processing
- Network interface and routing configuration
- direct tool execution for scan workflows
- MAC address resolution for optimal scanning

Classes:
    Masscan: Main tool class for Masscan integration
    MasscanScan: Luigi task for executing Masscan port scans
    ImportMasscanOutput: Luigi task for importing scan results

Functions:
    get_mac_address: Retrieve MAC address for IP addresses
    get_default_gateway: Determine default network gateway
    get_masscan_input: Prepare input configuration for Masscan

Constants:
    TCP (str): TCP protocol identifier
    UDP (str): UDP protocol identifier
"""

from functools import partial
import netifaces as ni
import re
import os
import netaddr
import xml.etree.ElementTree as ET
import logging
from typing import List, Dict, Set, Optional, Any, Union

from reverge_collector import scan_utils
from reverge_collector import data_model
from reverge_collector import tool_utils
from reverge_collector.proc_utils import process_wrapper
from reverge_collector.tool_spec import ToolSpec

# Protocol constants for network scanning
TCP: str = 'tcp'  # TCP protocol identifier
UDP: str = 'udp'  # UDP protocol identifier


class Masscan(ToolSpec):

    name = 'masscan'
    description = 'Masscan is a fast port scanner that can scan the entire Internet in under 6 minutes, transmitting 10 million packets per second. It is designed to be used for large-scale network scanning and is capable of scanning large ranges of IP addresses quickly.'
    project_url = 'https://github.com/robertdavidgraham/masscan'
    tags = ['port-scan', 'fast']
    collector_type = data_model.CollectorType.ACTIVE.value
    scan_order = 2
    args = '--rate 1000'
    input_records = [
        data_model.ServerRecordType.SUBNET,
        data_model.ServerRecordType.HOST,
    ]
    output_records = [
        data_model.ServerRecordType.HOST,
        data_model.ServerRecordType.PORT,
    ]

    def get_output_path(self, scan_input) -> str:
        return get_output_path(scan_input)

    def execute_scan(self, scan_input) -> None:
        execute_scan(scan_input)

    def parse_output(self, output_path: str, scan_input) -> list:
        return parse_masscan_xml(
            output_path,
            scan_input.current_tool_instance_id,
        )


def get_mac_address(ip_address: str) -> Optional[str]:
    """
    Retrieve the MAC address for a given IP address using ARP.

    This function uses the system's ARP table to resolve the MAC address
    for a specified IP address. It's primarily used to determine the
    router's MAC address for optimal Masscan configuration.

    Args:
        ip_address (str): IP address to resolve MAC address for

    Returns:
        Optional[str]: MAC address in colon-separated format (e.g., "aa:bb:cc:dd:ee:ff")
                      Returns None if MAC address cannot be resolved

    Example:
        >>> mac = get_mac_address("192.168.1.1")
        >>> if mac:
        ...     print(f"Router MAC: {mac}")
        ... else:
        ...     print("MAC address not found")

    Note:
        - Uses the system's 'arp' command to query the ARP table
        - Supports both colon and hyphen-separated MAC address formats
        - Returns None if the IP is not in the ARP table or command fails
    """

    ret = None
    # Run the arp command to get the ARP table entries
    arp_cmd = ["arp", "-n", ip_address]

    future = scan_utils.executor.submit(
        process_wrapper, cmd_args=arp_cmd, store_output=True)

    output = None
    try:
        output_json = future.result()
        output = output_json['stdout']
    except Exception:
        pass

    if output:
        # Use regular expression to extract the MAC address
        mac_regex = r"(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))"
        match = re.search(mac_regex, output)
        if match:
            ret = match.group(0)

    return ret


def get_default_gateway() -> Optional[str]:
    """
    Retrieve the default gateway IP address from system routing table.

    This function queries the system's network configuration to determine
    the default gateway IP address. This is used by Masscan to configure
    optimal routing for high-speed scanning operations.

    Returns:
        Optional[str]: Default gateway IP address (e.g., "192.168.1.1")
                      Returns None if default gateway cannot be determined

    Example:
        >>> gateway = get_default_gateway()
        >>> if gateway:
        ...     print(f"Default gateway: {gateway}")
        ... else:
        ...     print("Could not determine default gateway")

    Note:
        - Uses the netifaces library to query system network configuration
        - Looks for the default gateway in the AF_INET (IPv4) family
        - Returns None if no default gateway is configured or accessible
    """

    default_gateway = None
    try:
        # Retrieve the gateways in the system
        gws = ni.gateways()

        # Get the default gateway, typically found under 'default' and using the AF_INET family
        default_gateway = gws['default'][ni.AF_INET][0]

    except:
        pass

    return default_gateway


# Setup the inputs for masscan from the scan data
def get_masscan_input(scheduled_scan_obj: Any) -> Dict[str, Any]:
    """
    Prepare input configuration and files for Masscan execution.

    This function extracts target networks and ports from the scan scope and
    creates the necessary configuration files for Masscan. It prepares both
    the target list (IPs/subnets) and port configuration for scanning.

    Args:
        scheduled_scan_obj (Any): Scheduled scan object containing scan data and configuration

    Returns:
        Dict[str, Any]: Configuration dictionary containing:
            - config_path (str): Path to Masscan configuration file
            - input_path (str): Path to target IP/subnet file
            - tool_args (List[str]): Additional command-line arguments

    Example:
        >>> scan_obj = get_scheduled_scan()
        >>> config = get_masscan_input(scan_obj)
        >>> print(config['config_path'])  # "/tmp/mass_conf_scan123"
        >>> print(config['input_path'])   # "/tmp/mass_ips_scan123"

    Note:
        - Creates configuration files in the tool's input directory
        - Extracts ports from scan scope or discovered ports
        - Combines subnets and individual hosts into target list
        - Formats ports for Masscan configuration syntax
    """

    masscan_conf = {}
    scan_id = scheduled_scan_obj.id
    tool_name = scheduled_scan_obj.current_tool.name

    # Get the scan inputs
    scope_obj = scheduled_scan_obj.scan_data
    scan_port_list = scope_obj.get_port_number_list_from_scope()
    if len(scan_port_list) == 0:
        scan_port_list = scope_obj.get_port_number_list_from_port_map()

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

    # Init directory
    dir_path = scan_utils.init_tool_folder(tool_name, 'inputs', scan_id)

    # Create config files
    masscan_config_file = dir_path + os.path.sep + "mass_conf_" + scan_id
    masscan_ip_file = None
    if len(target_list) > 0:

        masscan_ip_file = dir_path + os.path.sep + "mass_ips_" + scan_id

        # Write subnets/IPs to file
        with open(masscan_ip_file, 'w') as mass_scan_fd:
            for target_inst in target_list:
                mass_scan_fd.write(target_inst + '\n')
    else:
        logging.getLogger(__name__).error("Target list is empty")

    # Construct ports conf line
    port_line = "ports = " + \
        tool_utils.consolidate_ports([str(p) for p in scan_port_list])

    # Write ports to config file
    with open(masscan_config_file, 'w') as mass_scan_conf:
        mass_scan_conf.write(port_line + '\n')

    # Set the tools args
    tool_args = scheduled_scan_obj.current_tool.args
    if tool_args:
        tool_args = tool_args.split(" ")

    masscan_conf = {'config_path': masscan_config_file,
                    'input_path': masscan_ip_file, 'tool_args': tool_args}
    return masscan_conf


def get_output_path(scan_input) -> str:
    scan_id = scan_input.id
    tool_name = scan_input.current_tool.name
    dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)
    return dir_path + os.path.sep + "mass_out_" + scan_id


def execute_scan(scan_input) -> None:
    output_file_path = get_output_path(scan_input)
    if os.path.exists(output_file_path):
        return

    scheduled_scan_obj = scan_input
    selected_interface = scheduled_scan_obj.selected_interface
    masscan_output_file_path = output_file_path

    scan_config_dict = get_masscan_input(scheduled_scan_obj)
    conf_file_path = scan_config_dict['config_path']
    ips_file_path = scan_config_dict['input_path']
    tool_args = scan_config_dict['tool_args']

    router_mac = None
    default_gateway_ip = get_default_gateway()
    if default_gateway_ip:
        mac_address = get_mac_address(default_gateway_ip)
        if mac_address:
            router_mac = mac_address.replace(":", "-")

    if conf_file_path and ips_file_path:
        command = []
        if os.name != 'nt':
            command.append("sudo")
        command_arr = [
            "masscan",
            "--open",
            "-oX",
            masscan_output_file_path,
            "-c",
            conf_file_path,
            "-iL",
            ips_file_path
        ]
        if selected_interface:
            int_name = selected_interface.name.strip()
            command_arr.extend(['-e', int_name])
        if router_mac:
            command_arr.extend(['--router-mac', router_mac])
        if tool_args and len(tool_args) > 0:
            command_arr.extend(tool_args)
        command.extend(command_arr)

        callback_with_tool_id = partial(
            scheduled_scan_obj.register_tool_executor,
            scheduled_scan_obj.current_tool_instance_id)
        future = scan_utils.executor.submit(
            process_wrapper,
            cmd_args=command,
            pid_callback=callback_with_tool_id)
        ret_dict = future.result()
        if ret_dict and 'exit_code' in ret_dict:
            exit_code = ret_dict['exit_code']
            if exit_code != 0:
                err_msg = ''
                if 'stderr' in ret_dict and ret_dict['stderr']:
                    err_msg = ret_dict['stderr']
                logging.getLogger(__name__).error(
                    "Masscan scan for scan ID %s exited with code %d: %s" % (scheduled_scan_obj.id, exit_code, err_msg))
                raise RuntimeError("Masscan scan for scan ID %s exited with code %d: %s" % (
                    scheduled_scan_obj.id, exit_code, err_msg))
    else:
        logging.getLogger(__name__).error("No targets to scan with masscan")
        with open(masscan_output_file_path, 'w') as f:
            pass


def parse_masscan_xml(
    xml_path: str,
    tool_instance_id: Optional[str] = None,
) -> List[Any]:
    """Parse a Masscan XML output file and return data_model Record objects.

    Args:
        xml_path:         Path to the Masscan XML output file.
        tool_instance_id: Value assigned to each record's
                          ``collection_tool_instance_id`` field.

    Returns:
        List of Host and Port data_model Record objects.
    """
    obj_arr: List[Any] = []
    if not (os.path.isfile(xml_path) and os.path.getsize(xml_path) > 0):
        logging.getLogger(__name__).error(
            'Masscan output file is empty or missing: %s', xml_path)
        return obj_arr

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for host in root.iter('host'):
            address = host.find('address')
            addr = address.get('addr')
            addr_type = address.get('addrtype')
            try:
                ip_addr = str(netaddr.IPAddress(addr))
            except netaddr.core.AddrFormatError:
                continue

            host_obj = data_model.Host()
            host_obj.collection_tool_instance_id = tool_instance_id
            if addr_type == 'ipv4':
                host_obj.ipv4_addr = ip_addr
            elif addr_type == 'ipv6':
                host_obj.ipv6_addr = ip_addr
            obj_arr.append(host_obj)

            ports_obj = host.find('ports')
            if ports_obj is None:
                continue
            for port in ports_obj.findall('port'):
                port_id_str = port.get('portid')
                proto_str = port.get('protocol', '').strip()
                proto = 0 if proto_str == TCP else 1
                port_obj = data_model.Port(parent_id=host_obj.id)
                port_obj.collection_tool_instance_id = tool_instance_id
                port_obj.proto = proto
                port_obj.port = port_id_str
                obj_arr.append(port_obj)

    except Exception as e:
        logging.getLogger(__name__).error(
            'Masscan results parsing error: %s', str(e))
        if os.path.exists(xml_path):
            os.remove(xml_path)
        raise

    return obj_arr
