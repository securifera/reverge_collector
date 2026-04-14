"""
Nmap network scanning module for the reverge_collector framework.

This module provides comprehensive network scanning capabilities using Nmap, the industry-standard
network discovery and security auditing tool. It implements port scanning, service detection,
OS fingerprinting, and SSL certificate analysis through direct tool execution.

The module supports both subnet-based and targeted scanning, with intelligent scan optimization
based on previous masscan results. It processes XML output to extract detailed host, port,
service, and certificate information.

Classes:
    Nmap: Tool configuration class for Nmap scanner
    NmapScan: Luigi task for executing Nmap network scans
    ImportNmapOutput: Luigi task for processing and importing Nmap scan results

Functions:
    remove_dups_from_dict: Utility function to remove duplicate script results

"""

from functools import partial
import json
import os
import shutil
import time
from datetime import datetime
from typing import Dict, Any, List, Set, Optional, Union
import netaddr
import traceback
import logging

from libnmap.parser import NmapParser
from reverge_collector import scan_utils
from reverge_collector import data_model
from reverge_collector import tool_utils
from reverge_collector.proc_utils import process_wrapper
from reverge_collector.tool_spec import ToolSpec


class Nmap(ToolSpec):

    name = 'nmap'
    description = 'Nmap is a network scanning tool used to discover hosts and services on a computer network. It can be used to perform port scanning, service detection, and OS detection.'
    project_url = 'https://github.com/nmap/nmap'
    tags = ['port-scan', 'service-detection', 'os-detection', 'slow']
    collector_type = data_model.CollectorType.ACTIVE.value
    scan_order = 6
    args = '-sT -sV --script +ssl-cert --script-args ssl=True'
    input_records = [
        data_model.ServerRecordType.SUBNET,
        data_model.ServerRecordType.HOST,
        data_model.ServerRecordType.PORT,
    ]
    output_records = [
        data_model.ServerRecordType.COLLECTION_MODULE,
        data_model.ServerRecordType.COLLECTION_MODULE_OUTPUT,
        data_model.ServerRecordType.WEB_COMPONENT,
        data_model.ServerRecordType.DOMAIN,
        data_model.ServerRecordType.CERTIFICATE,
        data_model.ServerRecordType.LIST_ITEM,
        data_model.ServerRecordType.PORT,
        data_model.ServerRecordType.HOST,
    ]

    def __init__(self):
        super().__init__()
        self.modules_func = Nmap.nmap_modules

    def get_output_path(self, scan_input) -> str:
        return get_output_path(scan_input)

    def execute_scan(self, scan_input) -> None:
        execute_scan(scan_input)

    def parse_output(self, output_path: str, scan_input) -> list:
        ret_arr = []
        with open(output_path) as f:
            json_input = f.read()
        if json_input:
            nmap_scan_obj = json.loads(json_input)
            scope_obj = scan_input.scan_data
            tool_instance_id = scan_input.current_tool_instance_id
            tool_id = scan_input.current_tool.id
            for entry in nmap_scan_obj.get('nmap_scan_list', []):
                nmap_out = entry['output_file']
                if os.path.exists(nmap_out) and os.path.getsize(nmap_out) > 0:
                    try:
                        ret_arr.extend(
                            parse_nmap_xml(nmap_out, scope_obj,
                                           tool_instance_id, tool_id)
                        )
                    except Exception:
                        logging.getLogger(__name__).error(
                            'Failed parsing nmap output: %s', nmap_out)
                        logging.getLogger(__name__).error(
                            traceback.format_exc())
                        try:
                            shutil.rmtree(os.path.dirname(output_path))
                        except Exception:
                            pass
                        raise
        return ret_arr

    @staticmethod
    def nmap_modules() -> List:
        """
        Retrieve available Nmap NSE scripts as collection modules.

        Executes 'nmap --script-help' to discover all available Nmap Scripting
        Engine (NSE) scripts and converts them to CollectionModule objects.
        Each script becomes a module that can be selectively enabled for scanning.

        Results are cached on disk and only regenerated when the ``nmap`` binary
        changes on disk (version upgrade / reinstall).

        Returns:
            List[data_model.CollectionModule]: List of collection modules, one for each NSE script

        Example:
            >>> nmap_tool = Nmap()
            >>> modules = nmap_tool.modules_func()
            >>> for module in modules:
            ...     print(f"{module.name}: {module.args}")
        """
        from reverge_collector.module_cache import get_cached_modules
        return get_cached_modules('nmap', Nmap._fingerprint,
                                  Nmap._generate_nmap_modules)

    @staticmethod
    def _fingerprint() -> Optional[str]:
        """Cache fingerprint: SHA-256 of the nmap binary."""
        from reverge_collector.module_cache import sha256_file
        path = shutil.which('nmap')
        if path and os.path.exists(path):
            return sha256_file(path)
        return None

    @staticmethod
    def _generate_nmap_modules() -> List:
        """Internal: enumerate NSE scripts without cache."""
        modules = []

        try:
            # Execute nmap --script-help to get list of all scripts
            cmd_args = ['nmap', '--script-help', 'all']
            result = process_wrapper(cmd_args=cmd_args, store_output=True)

            if result and 'exit_code' in result and result['exit_code'] != 0:
                logging.getLogger(__name__).warning(
                    f"nmap --script-help failed with exit code {result['exit_code']}"
                )
                return modules

            output = result.get('stdout', '') if result else ''

            # Parse the output - format is:
            # script-name
            # Categories: cat1 cat2 cat3
            # https://nmap.org/nsedoc/scripts/script-name.html
            #   Description (potentially multi-line, indented with tabs)
            # (blank line)

            lines = output.split('\n')
            i = 0

            while i < len(lines):
                line = lines[i]

                # Skip empty lines
                if not line.strip():
                    i += 1
                    continue

                # Line 1: Script name (not indented)
                if not line.startswith('\t') and not line.startswith(' '):
                    script_name = line.strip()

                    # Line 2: Categories
                    i += 1
                    if i < len(lines) and lines[i].startswith('Categories:'):
                        categories = lines[i].replace(
                            'Categories:', '').strip()
                    else:
                        categories = ''

                    # Line 3: URL
                    i += 1
                    if i < len(lines) and lines[i].startswith('http'):
                        url = lines[i].strip()
                    else:
                        url = ''

                    # Lines 4+: Description (indented lines until empty line)
                    description_parts = []
                    i += 1
                    while i < len(lines):
                        if not lines[i].strip():
                            # Empty line marks end of this script entry
                            break
                        if lines[i].startswith('\t') or lines[i].startswith('  '):
                            description_parts.append(lines[i].strip())
                        i += 1

                    # Create CollectionModule for this script
                    module = data_model.CollectionModule()
                    module.name = script_name
                    module.description = ' '.join(description_parts).strip()
                    module.args = f"--script +{script_name}"
                    modules.append(module)

                i += 1

        except FileNotFoundError:
            logging.getLogger(__name__).error("nmap command not found")
        except Exception as e:
            logging.getLogger(__name__).error(
                f"Error getting nmap modules: {str(e)}"
            )
            logging.getLogger(__name__).debug(traceback.format_exc())

        return modules


def get_output_path(scan_input) -> str:
    scan_id: str = scan_input.id
    tool_name: str = scan_input.current_tool.name
    dir_path: str = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)
    return dir_path + os.path.sep + "nmap_scan_" + scan_id + ".meta"


def execute_scan(scan_input) -> None:
    meta_file_path: str = get_output_path(scan_input)
    if os.path.exists(meta_file_path):
        return

    scheduled_scan_obj = scan_input
    selected_interface = scheduled_scan_obj.selected_interface
    dir_path: str = os.path.dirname(meta_file_path)
    scope_obj = scheduled_scan_obj.scan_data

    nmap_scan_data: Optional[Dict[str, Any]] = None
    nmap_scan_args: Optional[List[str]] = None
    if scheduled_scan_obj.current_tool.args:
        nmap_scan_args = scheduled_scan_obj.current_tool.args.split(" ")

    mass_scan_ran: bool = False
    for collection_tool in scheduled_scan_obj.collection_tool_map.values():
        if collection_tool.collection_tool.name == 'masscan':
            mass_scan_ran = True
            break

    nmap_scan_list: List[Dict[str, Any]] = []
    scan_port_map: Dict[str, Dict[str, Any]] = {}

    if mass_scan_ran:
        target_map: Dict[str, Dict[str, Any]] = scope_obj.host_port_obj_map
        for target_key in target_map:
            target_obj_dict = target_map[target_key]
            port_obj = target_obj_dict['port_obj']
            port_str: str = port_obj.port
            host_obj = target_obj_dict['host_obj']
            ip_addr: str = host_obj.ipv4_addr
            if port_str in scan_port_map:
                scan_obj = scan_port_map[port_str]
            else:
                scan_obj: Dict[str, Any] = {
                    'port_list': [str(port_str)],
                    'tool_args': nmap_scan_args,
                    'resolve_dns': False
                }
                scan_port_map[port_str] = scan_obj
            if 'ip_set' not in scan_obj:
                scan_obj['ip_set'] = set()
            ip_set: Set[str] = scan_obj['ip_set']
            ip_set.add(ip_addr)
            target_arr: List[str] = target_key.split(":")
            if target_arr[0] != ip_addr:
                domain_str: str = target_arr[0]
                scan_obj['resolve_dns'] = True
                ip_set.add(domain_str)
        nmap_scan_list.extend(list(scan_port_map.values()))
    else:
        target_map = scope_obj.host_port_obj_map
        port_num_list: List[str] = scope_obj.get_port_number_list_from_scope()
        subnet_map: Dict[int, Any] = scope_obj.subnet_map
        if len(subnet_map) > 0:
            for subnet_id in subnet_map:
                subnet_obj = subnet_map[subnet_id]
                subnet_str: str = "%s/%s" % (subnet_obj.subnet,
                                             subnet_obj.mask)
                scan_obj: Dict[str, Any] = {
                    'ip_set': [subnet_str],
                    'tool_args': nmap_scan_args,
                    'resolve_dns': False,
                    'port_list': list(set(port_num_list))
                }
                nmap_scan_list.append(scan_obj)
        elif len(target_map) > 0:
            for target_key in target_map:
                target_obj_dict = target_map[target_key]
                port_obj = target_obj_dict['port_obj']
                port_str = port_obj.port
                host_obj = target_obj_dict['host_obj']
                ip_addr = host_obj.ipv4_addr
                if port_str in scan_port_map:
                    scan_obj = scan_port_map[port_str]
                else:
                    scan_obj = {
                        'port_list': [str(port_str)],
                        'tool_args': nmap_scan_args,
                        'resolve_dns': False
                    }
                    scan_port_map[port_str] = scan_obj
                if 'ip_set' not in scan_obj:
                    scan_obj['ip_set'] = set()
                ip_set = scan_obj['ip_set']
                ip_set.add(ip_addr)
                target_arr = target_key.split(":")
                if target_arr[0] != ip_addr:
                    domain_str = target_arr[0]
                    scan_obj['resolve_dns'] = True
                    ip_set.add(domain_str)
            nmap_scan_list.extend(list(scan_port_map.values()))
        else:
            if len(port_num_list) > 0:
                scan_obj: Dict[str, Any] = {}
                target_set: Set[str] = set()
                resolve_dns: bool = False
                host_list = scope_obj.get_hosts(
                    [data_model.RecordTag.SCOPE.value, data_model.RecordTag.LOCAL.value])
                for host_obj in host_list:
                    ip_addr = host_obj.ipv4_addr
                    target_set.add(ip_addr)
                    if host_obj.id in scope_obj.domain_host_id_map:
                        temp_domain_list = scope_obj.domain_host_id_map[host_obj.id]
                        if len(temp_domain_list) > 0:
                            resolve_dns = True
                            for domain_obj in temp_domain_list:
                                domain_name: str = domain_obj.name
                                target_set.add(domain_name)
                domain_list = scope_obj.get_domains(
                    [data_model.RecordTag.SCOPE.value, data_model.RecordTag.LOCAL.value])
                for domain_obj in domain_list:
                    domain_name = domain_obj.name
                    target_set.add(domain_name)
                scan_obj['ip_set'] = target_set
                scan_obj['tool_args'] = nmap_scan_args
                scan_obj['resolve_dns'] = resolve_dns
                scan_obj['port_list'] = list(set(port_num_list))
                nmap_scan_list.append(scan_obj)

    nmap_scan_cmd_list: List[Dict[str, Any]] = []
    nmap_scan_data = {}
    counter: int = 0
    futures: List[Any] = []

    for scan_obj in nmap_scan_list:
        nmap_scan_inst: Dict[str, Any] = {}
        script_args: Optional[List[str]] = scan_obj.get('tool_args')
        port_list: List[str] = scan_obj['port_list']
        port_comma_list: str = tool_utils.consolidate_ports(port_list)
        ip_list_path: str = dir_path + os.path.sep + "nmap_in_" + str(counter)
        ip_list: Union[Set[str], List[str]] = scan_obj['ip_set']
        if len(ip_list) == 0:
            continue
        with open(ip_list_path, 'w') as in_file_fd:
            for ip in ip_list:
                in_file_fd.write(ip + "\n")
        nmap_output_xml_file: str = dir_path + \
            os.path.sep + "nmap_out_" + str(counter)
        command: List[str] = []
        if os.name != 'nt':
            command.append("sudo")
        command_arr: List[str] = [
            "nmap",
            "-v",
            "-Pn",
            "--open",
            "--host-timeout",
            "30m",
            "--script-timeout",
            "2m",
            "--script-args",
            'http.useragent="%s"' % scan_utils.custom_user_agent,
            "-p",
            port_comma_list,
            "-oX",
            nmap_output_xml_file,
            "-iL",
            ip_list_path
        ]
        if selected_interface:
            int_name: str = selected_interface.name.strip()
            command_arr.extend(['-e', int_name])
        command.extend(command_arr)
        resolve_dns: bool = scan_obj['resolve_dns']
        if not resolve_dns:
            command.append("-n")
        if script_args and len(script_args) > 0:
            command.extend(script_args)
        nmap_scan_inst['nmap_command'] = command
        nmap_scan_inst['output_file'] = nmap_output_xml_file
        nmap_scan_cmd_list.append(nmap_scan_inst)
        callback_with_tool_id = partial(
            scheduled_scan_obj.register_tool_executor,
            scheduled_scan_obj.current_tool_instance_id)
        futures.append(scan_utils.executor.submit(
            process_wrapper,
            cmd_args=command,
            pid_callback=callback_with_tool_id))
        counter += 1

    if len(futures) > 0:
        scan_proc_inst = data_model.ToolExecutor(futures)
        scheduled_scan_obj.register_tool_executor(
            scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)
        for future in futures:
            ret_dict = future.result()
            if ret_dict and 'exit_code' in ret_dict:
                exit_code = ret_dict['exit_code']
                if exit_code != 0:
                    err_msg = ''
                    if 'stderr' in ret_dict and ret_dict['stderr']:
                        err_msg = ret_dict['stderr']
                    logging.getLogger(__name__).error(
                        "Nmap scan for scan ID %s exited with code %d: %s" % (scheduled_scan_obj.id, exit_code, err_msg))
                    raise RuntimeError("Nmap scan for scan ID %s exited with code %d: %s" % (
                        scheduled_scan_obj.id, exit_code, err_msg))

    nmap_scan_data['nmap_scan_list'] = nmap_scan_cmd_list
    if nmap_scan_data:
        with open(meta_file_path, 'w') as meta_file_fd:
            meta_file_fd.write(json.dumps(nmap_scan_data))


# remove_dups_from_dict lives in reverge_collector.tool_utils


def parse_nmap_xml(
    xml_path: str,
    scope_obj: Optional[Any] = None,
    tool_instance_id: Optional[str] = None,
    tool_id: Optional[str] = None,
) -> List[Any]:
    """Parse a single nmap XML output file and return data_model Record objects.

    Args:
        xml_path:         Absolute path to the nmap XML output file.
        scope_obj:        Optional ScanData for ID correlation.  When ``None``
                          every record receives a fresh UUID.
        tool_instance_id: Value assigned to each record's
                          ``collection_tool_instance_id`` field.
        tool_id:          Parent ID for CollectionModule objects.

    Returns:
        Ordered list of data_model Record objects.
    """
    nmap_report = NmapParser.parse_fromfile(xml_path)
    ret_arr: List[Any] = []

    for host in nmap_report.hosts:
        host_ip: str = host.id
        host_id: Optional[str] = None

        for port_tuple in host.get_open_ports():
            port_str: str = str(port_tuple[0])
            port_service_id: str = port_tuple[1] + "." + port_str

            port_id: Optional[str] = None
            host_key: str = "%s:%s" % (host_ip, port_str)

            if scope_obj is not None:
                if host_key in scope_obj.host_port_obj_map:
                    host_port_dict = scope_obj.host_port_obj_map[host_key]
                    port_id = host_port_dict["port_obj"].id
                    host_id = host_port_dict["host_obj"].id
                elif host_ip in scope_obj.host_ip_id_map:
                    host_id = scope_obj.host_ip_id_map[host_ip]

            ip_object = netaddr.IPAddress(host_ip)
            host_obj = data_model.Host(id=host_id)
            host_obj.collection_tool_instance_id = tool_instance_id
            if ip_object.version == 4:
                host_obj.ipv4_addr = str(ip_object)
            elif ip_object.version == 6:
                host_obj.ipv6_addr = str(ip_object)
            host_id = host_obj.id
            ret_arr.append(host_obj)

            port_obj = data_model.Port(parent_id=host_id, id=port_id)
            port_obj.collection_tool_instance_id = tool_instance_id
            port_obj.proto = 0  # TCP
            port_obj.port = port_str
            port_id = port_obj.id
            ret_arr.append(port_obj)

            for hostname in host.hostnames:
                if type(hostname) is dict:
                    hostname = hostname["name"]
                domain_obj = data_model.Domain(parent_id=host_id)
                domain_obj.collection_tool_instance_id = tool_instance_id
                domain_obj.name = hostname
                ret_arr.append(domain_obj)

            svc = host.get_service_byid(port_service_id)
            if not svc:
                continue

            svc_dict: Dict[str, str] = svc.service_dict

            service_name: str = svc_dict.get("name", "")
            if service_name:
                component_name = service_name.lower().strip()
                if component_name and component_name != "unknown":
                    comp = data_model.WebComponent(parent_id=port_id)
                    comp.collection_tool_instance_id = tool_instance_id
                    comp.name = component_name
                    ret_arr.append(comp)

            product: str = svc_dict.get("product", "")
            if product:
                component_name = product.replace(" httpd", "").lower().strip()
                if component_name and component_name != "unknown":
                    comp = data_model.WebComponent(parent_id=port_id)
                    comp.collection_tool_instance_id = tool_instance_id
                    comp.name = component_name
                    version_str: str = svc_dict.get("version", "")
                    if version_str:
                        comp.version = version_str
                    ret_arr.append(comp)

            script_res_arr = svc.scripts_results
            if not script_res_arr:
                continue

            script_res = tool_utils.remove_dups_from_dict(script_res_arr)

            for script in script_res:
                script_id: str = script.get("id", "")

                if script_id == "ssl-cert":
                    port_obj.secure = True
                    cert_obj = data_model.Certificate(parent_id=port_obj.id)
                    cert_obj.collection_tool_instance_id = tool_instance_id

                    elements = script.get("elements", {})
                    validity = elements.get("validity", {})

                    if "notBefore" in validity:
                        try:
                            dt = datetime.strptime(
                                validity["notBefore"], "%Y-%m-%dT%H:%M:%S"
                            )
                            cert_obj.issued = int(time.mktime(dt.timetuple()))
                        except ValueError:
                            pass

                    if "notAfter" in validity:
                        try:
                            dt = datetime.strptime(
                                validity["notAfter"], "%Y-%m-%dT%H:%M:%S"
                            )
                            cert_obj.expires = int(time.mktime(dt.timetuple()))
                        except ValueError:
                            pass

                    if "sha1" in elements:
                        cert_obj.fingerprint_hash = elements["sha1"]

                    subject = elements.get("subject", {})
                    if "commonName" in subject:
                        domain_obj = cert_obj.add_domain(
                            host_id, subject["commonName"], tool_instance_id
                        )
                        if domain_obj:
                            ret_arr.append(domain_obj)

                    if "issuer" in elements:
                        cert_obj.issuer = json.dumps(elements["issuer"])

                    extensions = elements.get("extensions", {})
                    null_ext = extensions.get("null", [])
                    if not isinstance(null_ext, list):
                        null_ext = [null_ext]
                    for ext_inst in null_ext:
                        if not isinstance(ext_inst, dict):
                            continue
                        if ext_inst.get("name") == "X509v3 Subject Alternative Name":
                            san_value: str = ext_inst.get("value", "")
                            if ":" in san_value:
                                dns_name = san_value.split(":")[1]
                                if "," in dns_name:
                                    dns_name = dns_name.split(",")[0]
                                dns_name = dns_name.strip()
                                domain_obj = cert_obj.add_domain(
                                    host_id, dns_name, tool_instance_id
                                )
                                if domain_obj:
                                    ret_arr.append(domain_obj)

                    ret_arr.append(cert_obj)

                elif "http" in script_id:
                    comp = data_model.WebComponent(parent_id=port_id)
                    comp.collection_tool_instance_id = tool_instance_id
                    comp.name = "http"
                    ret_arr.append(comp)

            for script_out in script_res:
                if "id" not in script_out or "output" not in script_out:
                    continue
                script_id = script_out["id"]
                output: str = script_out["output"]
                if not output:
                    continue

                module_obj = data_model.CollectionModule(parent_id=tool_id)
                module_obj.collection_tool_instance_id = tool_instance_id
                module_obj.name = script_id
                module_obj.args = "--script +%s" % script_id
                ret_arr.append(module_obj)
                temp_module_id = module_obj.id

                module_output_obj = data_model.CollectionModuleOutput(
                    parent_id=temp_module_id
                )
                module_output_obj.collection_tool_instance_id = tool_instance_id
                module_output_obj.output = output
                module_output_obj.port_id = port_id
                ret_arr.append(module_output_obj)

    return ret_arr
