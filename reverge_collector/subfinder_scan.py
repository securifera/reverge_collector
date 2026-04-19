"""
Subfinder Scan Module

This module integrates Subfinder, a subdomain discovery tool, into the reverge_collector
security scanning framework. It provides passive subdomain enumeration using
various online sources and APIs.

Subfinder is a subdomain discovery tool that finds valid subdomains for websites
using passive online sources. It has a simple, modular architecture and is
optimized for speed.

The module includes:
- Subfinder tool integration and configuration
- Subdomain discovery and DNS resolution
- API key management for enhanced results
- direct tool execution for scan workflows
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
import traceback
import os.path
import yaml
import logging
from typing import List, Dict, Set, Optional, Any, Tuple

from reverge_collector import scan_utils
from reverge_collector import data_model
from reverge_collector.proc_utils import process_wrapper
from reverge_collector.tool_spec import ToolSpec


class Subfinder(ToolSpec):

    name = 'subfinder'
    description = 'subfinder is a subdomain discovery tool that returns valid subdomains for websites, using passive online sources. It has a simple, modular architecture and is optimized for speed.'
    project_url = 'https://github.com/projectdiscovery/subfinder'
    tags = ['passive', 'dns-enum']
    collector_type = data_model.CollectorType.PASSIVE.value
    scan_order = 1
    args = '-all'
    input_records = [data_model.ServerRecordType.DOMAIN]
    output_records = [
        data_model.ServerRecordType.HOST,
        data_model.ServerRecordType.DOMAIN,
    ]

    def get_output_path(self, scan_input) -> str:
        return get_output_path(scan_input)

    def execute_scan(self, scan_input) -> None:
        execute_scan(scan_input)

    def parse_output(self, output_path: str, scan_input) -> list:
        return parse_subfinder_output(
            output_path,
            scan_input.current_tool_instance_id,
        )


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
        cmd_args=command, use_shell=use_shell, my_env=my_env, pid_callback=callback_with_tool_id)

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
        domain_name = domain_entry.get('host', '').strip()
        ip_str = domain_entry.get('ip', '').strip()
        if not domain_name or not ip_str:
            # subfinder emits empty ip for unresolved domains — skip them
            # so they don't corrupt the ip_map with an empty-string key
            logging.getLogger(__name__).debug(
                "Subfinder: skipping entry with missing host/ip: %s", domain_entry)
            continue
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
        >>> tools = [chaos_tool, shodan_tool]
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

    api_key_arr = ['chaos', 'shodan']
    if collection_tools:
        for collection_tool_inst in collection_tools:
            collection_tool = collection_tool_inst.collection_tool
            if collection_tool.name in api_key_arr and collection_tool_inst.api_key:
                data[collection_tool.name] = [collection_tool_inst.api_key]

    # Write to config file
    with open(config_file_path, 'w') as yaml_file:
        yaml_file.write(yaml.dump(data, default_flow_style=False))


def get_output_path(scan_input: Any) -> str:
    scan_id = scan_input.id
    tool_name = scan_input.current_tool.name
    dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)
    return f"{dir_path}{os.path.sep}subfinder_outputs_{scan_id}.json"


def execute_scan(scan_input: Any) -> None:
    meta_file_path = get_output_path(scan_input)
    if os.path.exists(meta_file_path):
        logging.getLogger(__name__).debug(
            "Output path %s already exists, skipping Subfinder scan execution", meta_file_path)
        return

    scheduled_scan_obj = scan_input
    dns_scan_obj = get_subfinder_input(scheduled_scan_obj)

    tool_args = scheduled_scan_obj.current_tool.args
    if tool_args:
        tool_args = tool_args.split(" ")

    dir_path = os.path.dirname(meta_file_path)

    # Write out meta data file
    ret_list = []

    subfinder_domain_list = dns_scan_obj['input_path']

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
        ret_list.extend(scan_utils.dns_wrapper(domain_set))

    # Write the output file
    with open(meta_file_path, 'w') as output_fd:
        output_fd.write(json.dumps({'domain_list': ret_list}))


def parse_subfinder_output(
    output_file: str,
    tool_instance_id: Optional[str] = None,
) -> List[Any]:
    """Parse a Subfinder JSON output file and return data_model Record objects."""

    with open(output_file, 'r') as file_fd:
        data = file_fd.read()

    obj_map: Dict[str, Any] = {}

    if len(data) > 0:
        domain_map = json.loads(data)

        if 'domain_list' in domain_map:
            domain_list = domain_map['domain_list']

            ip_map: Dict[str, Set[str]] = {}

            for domain_entry in domain_list:
                domain_str = domain_entry['domain']
                ip_str = domain_entry['ip']

                if ip_str in ip_map:
                    domain_list_for_ip = ip_map[ip_str]
                else:
                    domain_list_for_ip = set()
                    ip_map[ip_str] = domain_list_for_ip

                domain_list_for_ip.add(domain_str)

            for ip_addr in ip_map:
                domain_set = ip_map[ip_addr]
                domains = list(domain_set)

                try:
                    ip_object = netaddr.IPAddress(ip_addr)
                except (netaddr.AddrFormatError, ValueError):
                    logging.getLogger(__name__).debug(
                        "Subfinder: skipping unparseable IP %r for domains %s", ip_addr, domains)
                    continue

                host_obj = data_model.Host()
                host_obj.collection_tool_instance_id = tool_instance_id

                if ip_object.version == 4:
                    host_obj.ipv4_addr = str(ip_object)
                elif ip_object.version == 6:
                    host_obj.ipv6_addr = str(ip_object)

                obj_map[host_obj.id] = host_obj

                for domain in domains:
                    domain_obj = data_model.Domain(parent_id=host_obj.id)
                    domain_obj.collection_tool_instance_id = tool_instance_id
                    domain_obj.name = domain
                    obj_map[domain_obj.id] = domain_obj

    return list(obj_map.values())
