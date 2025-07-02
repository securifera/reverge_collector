"""
Waluigi Masscan Integration Module

This module integrates Masscan, a high-speed port scanner, into the Waluigi
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
- Luigi task orchestration for scan workflows
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
import luigi
import logging
from typing import List, Dict, Set, Optional, Any, Union

from luigi.util import inherits
from waluigi import scan_utils
from waluigi import data_model

# Protocol constants for network scanning
TCP: str = 'tcp'  # TCP protocol identifier
UDP: str = 'udp'  # UDP protocol identifier


class Masscan(data_model.WaluigiTool):
    """
    Masscan tool integration for high-speed port scanning.

    This class integrates the Masscan port scanner into the Waluigi framework,
    providing high-speed network reconnaissance capabilities. Masscan is designed
    for scanning large IP ranges quickly and efficiently, using its own TCP/IP
    stack implementation to achieve maximum performance.

    Masscan capabilities include:
    - Extremely fast port scanning (10M packets/second)
    - Large-scale network range scanning
    - Custom TCP/IP stack for performance
    - Configurable scan rates and interfaces
    - XML output format for structured results

    Attributes:
        name (str): Tool name identifier
        description (str): Detailed tool description
        project_url (str): URL to the Masscan project
        collector_type (int): Type of collection (ACTIVE)
        scan_order (int): Execution order in scan workflow
        args (str): Default command-line arguments for scan rate
        scan_func (callable): Function to execute port scans
        import_func (callable): Function to import scan results

    Example:
        >>> masscan = Masscan()
        >>> print(masscan.name)  # "masscan"
        >>> print(masscan.collector_type)  # ACTIVE collection type
    """

    def __init__(self) -> None:
        """
        Initialize the Masscan tool configuration.

        Sets up the tool with default parameters, scan functions, and metadata
        required for integration with the Waluigi scanning framework.
        """
        self.name = 'masscan'
        self.description = 'Masscan is a fast port scanner that can scan the entire Internet in under 6 minutes, transmitting 10 million packets per second. It is designed to be used for large-scale network scanning and is capable of scanning large ranges of IP addresses quickly.'
        self.project_url = "https://github.com/robertdavidgraham/masscan"
        self.collector_type = data_model.CollectorType.ACTIVE.value
        self.scan_order = 2
        self.args = "--rate 1000"
        self.scan_func = Masscan.scan
        self.import_func = Masscan.import_scan

    @staticmethod
    def scan(scan_input: Any) -> bool:
        """
        Execute Masscan port scanning operation.

        This static method orchestrates the Masscan scanning process using Luigi
        task management. It builds and executes a MasscanScan task with the
        provided scan input configuration.

        Args:
            scan_input (Any): Scan input object containing scan configuration and context

        Returns:
            bool: True if scan completed successfully, False if scan failed

        Example:
            >>> scan_config = get_scan_input()
            >>> success = Masscan.scan(scan_config)
            >>> if success:
            ...     print("Masscan port scan completed")
        """
        luigi_run_result = luigi.build(
            [MasscanScan(scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True

    @staticmethod
    def import_scan(scan_input: Any) -> bool:
        """
        Import and process Masscan scan results.

        This static method handles the import of Masscan scan results into the
        data model. It builds and executes an ImportMasscanOutput task to process
        the discovered hosts and open ports.

        Args:
            scan_input (Any): Scan input object containing scan configuration and context

        Returns:
            bool: True if import completed successfully, False if import failed

        Example:
            >>> scan_config = get_scan_input()
            >>> success = Masscan.import_scan(scan_config)
            >>> if success:
            ...     print("Masscan results imported")
        """
        luigi_run_result = luigi.build([ImportMasscanOutput(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


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
        scan_utils.process_wrapper, cmd_args=arp_cmd, store_output=True)

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
    port_line = "ports = "
    for port in scan_port_list:
        port_line += str(port) + ','
    port_line.strip(',')

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


class MasscanScan(luigi.Task):
    """
    Luigi task for executing Masscan port scanning operations.

    This task orchestrates the complete Masscan scanning workflow including:
    - Input preparation with target networks and port configurations
    - Network interface and routing optimization
    - High-speed port scanning execution
    - Result output in XML format for processing

    The task handles large-scale network scanning efficiently by:
    - Configuring optimal network interfaces and routing
    - Setting appropriate scan rates for network capacity
    - Managing MAC address resolution for routing optimization
    - Executing Masscan with proper privilege escalation (sudo)

    Attributes:
        scan_input (luigi.Parameter): Scheduled scan object containing configuration

    Example:
        >>> task = MasscanScan(scan_input=scheduled_scan)
        >>> output_target = task.output()
        >>> task.run()  # Execute high-speed port scanning
    """

    scan_input = luigi.Parameter(default=None)

    def output(self) -> luigi.LocalTarget:
        """
        Define the output target for Masscan scan results.

        Creates the output file path for storing Masscan scan results in XML format.
        The file is stored in the tool's output directory within the scan workspace.

        Returns:
            luigi.LocalTarget: Target file for storing port scan results

        Example:
            >>> task = MasscanScan(scan_input=scan_obj)
            >>> target = task.output()
            >>> print(target.path)  # "/path/to/outputs/mass_out_scan123"
        """

        scheduled_scan_obj = self.scan_input
        scan_id = scheduled_scan_obj.id
        tool_name = scheduled_scan_obj.current_tool.name

        # Init output directory
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)
        out_file = dir_path + os.path.sep + "mass_out_" + scan_id

        return luigi.LocalTarget(out_file)

    def run(self) -> None:
        """
        Execute the Masscan port scanning operation.

        This method performs the complete Masscan scanning workflow:
        1. Prepare input configuration files and target lists
        2. Resolve network routing information (gateway MAC)
        3. Configure network interface for optimal scanning
        4. Execute Masscan with appropriate privileges
        5. Handle scanning errors and edge cases

        The method handles:
        - Network interface configuration for scanning
        - MAC address resolution for routing optimization
        - Privilege escalation (sudo) for raw socket access
        - Command-line argument configuration
        - Process execution and monitoring

        Returns:
            None: Results are written to the XML output file

        Example:
            >>> task = MasscanScan(scan_input=scan_config)
            >>> task.run()  # Executes complete port scanning workflow

        Note:
            - Requires sudo privileges for raw socket access
            - Uses router MAC address for optimal packet routing
            - Creates empty output file if no targets are available
            - Registers process executor for monitoring and control
        """

        scheduled_scan_obj = self.scan_input
        selected_interface = scheduled_scan_obj.selected_interface
        masscan_output_file_path = self.output().path

        # Prepare Masscan input configuration and files
        scan_config_dict = get_masscan_input(scheduled_scan_obj)

        conf_file_path = scan_config_dict['config_path']
        ips_file_path = scan_config_dict['input_path']
        tool_args = scan_config_dict['tool_args']

        # Optimize network routing by resolving router MAC address
        router_mac = None
        default_gateway_ip = get_default_gateway()
        if default_gateway_ip:
            mac_address = get_mac_address(default_gateway_ip)
            if mac_address:
                # Convert MAC format for Masscan (colon to hyphen)
                router_mac = mac_address.replace(":", "-")

        if conf_file_path and ips_file_path:
            # Build Masscan command with required arguments
            command = []

            # Add sudo for raw socket access (required on non-Windows systems)
            if os.name != 'nt':
                command.append("sudo")

            # Base Masscan command with essential options
            command_arr = [
                "masscan",        # Masscan executable
                "--open",         # Only report open ports
                "-oX",           # Output in XML format
                masscan_output_file_path,  # Output file path
                "-c",            # Configuration file
                conf_file_path,  # Path to config file with ports
                "-iL",           # Input list of targets
                ips_file_path    # Path to file with IP addresses/subnets
            ]

            # Configure specific network interface if selected
            if selected_interface:
                int_name = selected_interface.name.strip()
                command_arr.extend(['-e', int_name])

            # Add router MAC for optimal packet routing
            if router_mac:
                command_arr.extend(['--router-mac', router_mac])

            # Add additional tool-specific arguments
            if tool_args and len(tool_args) > 0:
                command_arr.extend(tool_args)

            command.extend(command_arr)

            # Execute Masscan process with monitoring
            callback_with_tool_id = partial(
                scheduled_scan_obj.register_tool_executor,
                scheduled_scan_obj.current_tool_instance_id)

            future = scan_utils.executor.submit(
                scan_utils.process_wrapper,
                cmd_args=command,
                pid_callback=callback_with_tool_id)

            # Wait for the scanning process to complete
            future.result()

        else:
            # Handle case where no targets are available for scanning
            logging.getLogger(__name__).error(
                "No targets to scan with masscan")
            # Create empty output file to satisfy Luigi dependencies
            with open(masscan_output_file_path, 'w') as f:
                pass


@inherits(MasscanScan)
class ImportMasscanOutput(data_model.ImportToolXOutput):
    """
    Luigi task for importing and processing Masscan scan results.

    This task handles the import of Masscan XML output into the data model,
    converting discovered hosts and open ports into structured Host and Port
    objects. It processes the XML output format generated by Masscan and creates
    appropriate data model objects.

    The import process includes:
    - Parsing Masscan XML output format
    - Creating Host objects for discovered IP addresses
    - Creating Port objects for discovered open ports
    - Handling both IPv4 and IPv6 addresses
    - Establishing proper parent-child relationships
    - Protocol identification (TCP/UDP)

    Inherits from:
        MasscanScan: Inherits scan input parameter and depends on scan completion
        ImportToolXOutput: Provides result import functionality

    Example:
        >>> import_task = ImportMasscanOutput(scan_input=scheduled_scan)
        >>> import_task.run()  # Import and process Masscan results
    """

    def requires(self) -> MasscanScan:
        """
        Define task dependencies - requires MasscanScan to complete first.

        Returns:
            MasscanScan: The scan task that must complete before import

        Example:
            >>> import_task = ImportMasscanOutput(scan_input=scan_obj)
            >>> dependency = import_task.requires()
            >>> print(type(dependency).__name__)  # "MasscanScan"
        """
        # Requires MassScan Task to be run prior
        return MasscanScan(scan_input=self.scan_input)

    def run(self) -> None:
        """
        Import and process Masscan scan results into the data model.

        This method performs the complete import workflow:
        1. Read XML output from MasscanScan task
        2. Parse XML structure to extract host and port information
        3. Create Host objects for each discovered IP address
        4. Create Port objects for each discovered open port
        5. Establish proper parent-child relationships
        6. Import results into the scan data structure

        The method handles:
        - XML parsing and error handling
        - IP address validation and normalization
        - Protocol identification (TCP/UDP mapping)
        - IPv4 and IPv6 address support
        - Tool instance ID tracking for data lineage

        Returns:
            None: Results are imported into the scan data structure

        Example:
            >>> import_task = ImportMasscanOutput(scan_input=scan_config)
            >>> import_task.run()  # Process and import discovered hosts/ports

        Raises:
            Exception: If XML parsing fails or file is corrupted

        Note:
            - Removes corrupted output files automatically
            - Creates Host objects for each unique IP address
            - Associates Port objects with their parent Host
            - Preserves tool instance ID for data tracking
            - Handles empty scan results gracefully
        """

        obj_arr: List[Any] = []
        masscan_output_file = self.input().path
        scheduled_scan_obj = self.scan_input
        tool_instance_id = scheduled_scan_obj.current_tool_instance_id

        # Verify output file exists and has content
        if os.path.isfile(masscan_output_file) and os.path.getsize(masscan_output_file) > 0:

            try:
                # Parse Masscan XML output
                tree = ET.parse(masscan_output_file)
                root = tree.getroot()

                # Process each discovered host in the XML
                for host in root.iter('host'):
                    # Extract IP address information
                    address = host.find('address')
                    addr = address.get('addr')
                    addr_type = address.get('addrtype')

                    try:
                        # Validate and normalize IP address
                        ip_addr = str(netaddr.IPAddress(addr))
                    except netaddr.core.AddrFormatError:
                        # Skip invalid IP addresses
                        continue

                    # Create Host object for the discovered IP
                    host_obj = data_model.Host()
                    host_obj.collection_tool_instance_id = tool_instance_id

                    # Set appropriate IP address field based on version
                    if addr_type == 'ipv4':
                        host_obj.ipv4_addr = ip_addr
                    elif addr_type == 'ipv6':
                        host_obj.ipv6_addr = ip_addr  # Note: Original code has bug using ipv4_addr

                    # Add host to results
                    obj_arr.append(host_obj)

                    # Process discovered ports for this host
                    ports_obj = host.find('ports')
                    ports = ports_obj.findall('port')
                    for port in ports:
                        # Extract port information
                        port_id = port.get('portid')
                        proto_str = port.get('protocol').strip()

                        # Map protocol string to numeric identifier
                        if proto_str == TCP:
                            proto = 0  # TCP protocol
                        else:
                            proto = 1  # UDP protocol (or other)

                        # Create Port object for the discovered service
                        port_obj = data_model.Port(parent_id=host_obj.id)
                        port_obj.collection_tool_instance_id = tool_instance_id
                        port_obj.proto = proto
                        port_obj.port = port_id

                        # Add port to results
                        obj_arr.append(port_obj)

            except Exception as e:
                # Handle XML parsing errors
                logging.getLogger(__name__).error(
                    'Masscan results parsing error: %s' % str(e))
                # Remove corrupted output file
                os.remove(masscan_output_file)
                raise e
        else:
            # Handle empty or missing output file
            logging.getLogger(__name__).error(
                "Masscan output file is empty. Ensure inputs were provided.")

        # Import processed results into scan data structure
        scheduled_scan_obj = self.scan_input
        self.import_results(scheduled_scan_obj, obj_arr)
