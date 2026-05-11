"""
Naabu port scanning and service detection module for the reverge_collector framework.

Naabu is a fast port scanner written in Go that supports service detection via
nmap-compatible probe files.  It can identify open ports, TLS endpoints, and
service versions without requiring root privileges (using TCP connect scans).

Classes:
    Naabu: Tool configuration class for the Naabu scanner

Functions:
    get_output_path: Return the path for this tool's meta output file
    execute_scan:    Run naabu against the current scan targets
    parse_naabu_output: Parse a single naabu JSONL output file into data_model objects
"""

from functools import partial
import json
import os
import shutil
import traceback
import logging
from typing import Dict, Any, List, Set, Optional, Union

import netaddr

from reverge_collector import scan_utils
from reverge_collector import data_model
from reverge_collector import tool_utils
from reverge_collector.proc_utils import process_wrapper
from reverge_collector.tool_spec import ToolSpec


class Naabu(ToolSpec):

    name = 'naabu'
    description = (
        'Naabu is a fast port scanner with service detection capabilities. '
        'It uses TCP connect scans (no raw sockets required) and can identify '
        'service versions using nmap-compatible probe files.'
    )
    project_url = 'https://github.com/projectdiscovery/naabu'
    tags = ['port-scan', 'service-detection']
    collector_type = data_model.CollectorType.ACTIVE.value
    scan_order = 4
    args = '-sD -sV'
    input_records = [
        data_model.ServerRecordType.SUBNET,
        data_model.ServerRecordType.HOST,
        data_model.ServerRecordType.PORT,
    ]
    output_records = [
        data_model.ServerRecordType.HOST,
        data_model.ServerRecordType.PORT,
        data_model.ServerRecordType.WEB_COMPONENT,
        data_model.ServerRecordType.DOMAIN,
    ]

    def get_output_path(self, scan_input) -> str:
        return get_output_path(scan_input)

    def execute_scan(self, scan_input) -> None:
        execute_scan(scan_input)

    def parse_output(self, output_path: str, scan_input) -> list:
        ret_arr = []
        with open(output_path) as f:
            json_input = f.read()
        if json_input:
            naabu_scan_obj = json.loads(json_input)
            scope_obj = scan_input.scan_data
            tool_instance_id = scan_input.current_tool_instance_id
            for entry in naabu_scan_obj.get('naabu_scan_list', []):
                naabu_out = entry['output_file']
                if os.path.exists(naabu_out) and os.path.getsize(naabu_out) > 0:
                    try:
                        ret_arr.extend(
                            parse_naabu_output(naabu_out, scope_obj,
                                               tool_instance_id)
                        )
                    except Exception:
                        logging.getLogger(__name__).error(
                            'Failed parsing naabu output: %s', naabu_out)
                        logging.getLogger(__name__).error(
                            traceback.format_exc())
                        try:
                            shutil.rmtree(os.path.dirname(output_path))
                        except Exception:
                            pass
                        raise
        return ret_arr


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def get_output_path(scan_input) -> str:
    scan_id: str = scan_input.id
    tool_name: str = scan_input.current_tool.name
    dir_path: str = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)
    return dir_path + os.path.sep + "naabu_scan_" + scan_id + ".meta"


def _cpe22_to_cpe23(cpe22: str) -> str:
    """Convert a CPE 2.2 URI binding to a CPE 2.3 formatted string (best-effort).

    Examples:
        ``cpe:/a:apache:http_server/``    → ``cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*``
        ``cpe:/a:openbsd:openssh:9.6p1/`` → ``cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*``
    """
    if not cpe22.startswith('cpe:/'):
        return cpe22
    body = cpe22[5:].rstrip('/')
    parts = body.split(':')
    # parts: [part, vendor, product, version?, ...]
    part = parts[0] if parts else '*'
    components = ['cpe', '2.3', part] + list(parts[1:4])
    # Pad to the 13-component CPE 2.3 structure
    while len(components) < 13:
        components.append('*')
    return ':'.join(components)


def execute_scan(scan_input) -> None:
    meta_file_path: str = get_output_path(scan_input)
    if os.path.exists(meta_file_path):
        logging.getLogger(__name__).debug(
            'Output path %s already exists, skipping naabu scan execution',
            meta_file_path)
        return

    scheduled_scan_obj = scan_input
    selected_interface = scheduled_scan_obj.selected_interface
    dir_path: str = os.path.dirname(meta_file_path)
    scope_obj = scheduled_scan_obj.scan_data

    naabu_scan_args: Optional[List[str]] = None
    if scheduled_scan_obj.current_tool.args:
        naabu_scan_args = scheduled_scan_obj.current_tool.args.split()

    mass_scan_ran: bool = any(
        ct.collection_tool.name == 'masscan'
        for ct in scheduled_scan_obj.collection_tool_map.values()
    )

    naabu_scan_list: List[Dict[str, Any]] = []
    scan_port_map: Dict[str, Dict[str, Any]] = {}

    if mass_scan_ran:
        target_map: Dict[str, Dict[str, Any]] = scope_obj.host_port_obj_map
        for target_key, target_obj_dict in target_map.items():
            port_obj = target_obj_dict['port_obj']
            port_str: str = port_obj.port
            host_obj = target_obj_dict['host_obj']
            ip_addr: str = host_obj.ipv4_addr
            if port_str not in scan_port_map:
                scan_port_map[port_str] = {
                    'port_list': [port_str],
                    'tool_args': naabu_scan_args,
                    'ip_set': set(),
                }
            ip_set: Set[str] = scan_port_map[port_str]['ip_set']
            ip_set.add(ip_addr)
            target_arr = target_key.split(':')
            if target_arr[0] != ip_addr:
                ip_set.add(target_arr[0])
        naabu_scan_list.extend(scan_port_map.values())
    else:
        target_map = scope_obj.host_port_obj_map
        port_num_list: List[str] = scope_obj.get_port_number_list_from_scope()
        subnet_map: Dict[int, Any] = scope_obj.subnet_map

        if subnet_map:
            for subnet_obj in subnet_map.values():
                subnet_str = '%s/%s' % (subnet_obj.subnet, subnet_obj.mask)
                naabu_scan_list.append({
                    'ip_set': [subnet_str],
                    'tool_args': naabu_scan_args,
                    'port_list': list(set(port_num_list)),
                })
        elif target_map:
            for target_key, target_obj_dict in target_map.items():
                port_obj = target_obj_dict['port_obj']
                port_str = port_obj.port
                host_obj = target_obj_dict['host_obj']
                ip_addr = host_obj.ipv4_addr
                if port_str not in scan_port_map:
                    scan_port_map[port_str] = {
                        'port_list': [port_str],
                        'tool_args': naabu_scan_args,
                        'ip_set': set(),
                    }
                ip_set = scan_port_map[port_str]['ip_set']
                ip_set.add(ip_addr)
                target_arr = target_key.split(':')
                if target_arr[0] != ip_addr:
                    ip_set.add(target_arr[0])
            naabu_scan_list.extend(scan_port_map.values())
        else:
            if port_num_list:
                target_set: Set[str] = set()
                host_list = scope_obj.get_hosts(
                    [data_model.RecordTag.SCOPE.value,
                     data_model.RecordTag.LOCAL.value])
                for h in host_list:
                    target_set.add(h.ipv4_addr)
                    if h.id in scope_obj.domain_host_id_map:
                        for d in scope_obj.domain_host_id_map[h.id]:
                            target_set.add(d.name)
                for d in scope_obj.get_domains(
                        [data_model.RecordTag.SCOPE.value,
                         data_model.RecordTag.LOCAL.value]):
                    target_set.add(d.name)
                naabu_scan_list.append({
                    'ip_set': target_set,
                    'tool_args': naabu_scan_args,
                    'port_list': list(set(port_num_list)),
                })

    naabu_scan_cmd_list: List[Dict[str, Any]] = []
    futures: List[Any] = []
    counter: int = 0

    for scan_obj in naabu_scan_list:
        ip_list: Union[Set[str], List[str]] = scan_obj['ip_set']
        if not ip_list:
            continue

        port_list: List[str] = scan_obj['port_list']
        port_comma_list: str = tool_utils.consolidate_ports(port_list)
        ip_list_path = dir_path + os.path.sep + 'naabu_in_' + str(counter)
        naabu_output_file = dir_path + \
            os.path.sep + 'naabu_out_' + str(counter)

        with open(ip_list_path, 'w') as fh:
            for ip in ip_list:
                fh.write(ip + '\n')

        command: List[str] = [
            'naabu',
            '-l', ip_list_path,
            '-p', port_comma_list,
            '-j',
            '-silent',
            '-o', naabu_output_file,
        ]

        if selected_interface:
            command.extend(['-interface', selected_interface.name.strip()])

        extra_args: Optional[List[str]] = scan_obj.get('tool_args')
        if extra_args:
            command.extend(extra_args)

        naabu_scan_cmd_list.append({
            'naabu_command': command,
            'output_file': naabu_output_file,
        })

        callback = partial(
            scheduled_scan_obj.register_tool_executor,
            scheduled_scan_obj.current_tool_instance_id)
        futures.append(scan_utils.executor.submit(
            process_wrapper,
            cmd_args=command,
            pid_callback=callback))
        counter += 1

    if futures:
        scan_proc_inst = data_model.ToolExecutor(futures)
        scheduled_scan_obj.register_tool_executor(
            scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)
        for future in futures:
            ret_dict = future.result()
            if ret_dict and ret_dict.get('exit_code', 0) != 0:
                err_msg = ret_dict.get('stderr', '')
                logging.getLogger(__name__).error(
                    'Naabu scan for scan ID %s exited with code %d: %s',
                    scheduled_scan_obj.id, ret_dict['exit_code'], err_msg)
                raise RuntimeError(
                    'Naabu scan for scan ID %s exited with code %d: %s' % (
                        scheduled_scan_obj.id, ret_dict['exit_code'], err_msg))

    naabu_scan_data = {'naabu_scan_list': naabu_scan_cmd_list}
    with open(meta_file_path, 'w') as mf:
        mf.write(json.dumps(naabu_scan_data))


def parse_naabu_output(
    output_path: str,
    scope_obj: Optional[Any] = None,
    tool_instance_id: Optional[str] = None,
) -> List[Any]:
    """Parse a single naabu JSONL output file and return data_model Record objects.

    Each line in the file is a JSON object with fields: host, ip, port, protocol,
    tls, name, product, version, cpes, etc.

    Args:
        output_path:      Absolute path to the naabu JSONL output file.
        scope_obj:        Optional ScanData for ID correlation.
        tool_instance_id: Value assigned to each record's
                          ``collection_tool_instance_id`` field.

    Returns:
        Ordered list of data_model Record objects.
    """
    ret_arr: List[Any] = []

    with open(output_path) as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                logging.getLogger(__name__).warning(
                    'Skipping non-JSON line in naabu output: %s', line[:120])
                continue

            ip: str = entry.get('ip', '')
            host: str = entry.get('host', '')
            port_num = entry.get('port')
            tls: bool = entry.get('tls', False)

            if not ip or port_num is None:
                continue

            port_str = str(port_num)
            host_key = '%s:%s' % (ip, port_str)

            host_id: Optional[str] = None
            port_id: Optional[str] = None

            if scope_obj is not None:
                if host_key in scope_obj.host_port_obj_map:
                    host_port_dict = scope_obj.host_port_obj_map[host_key]
                    port_id = host_port_dict['port_obj'].id
                    host_id = host_port_dict['host_obj'].id
                elif ip in scope_obj.host_ip_id_map:
                    host_id = scope_obj.host_ip_id_map[ip]

            try:
                ip_object = netaddr.IPAddress(ip)
            except netaddr.AddrFormatError:
                logging.getLogger(__name__).warning(
                    'Skipping invalid IP address: %s', ip)
                continue

            host_obj = data_model.Host(id=host_id)
            host_obj.collection_tool_instance_id = tool_instance_id
            if ip_object.version == 4:
                host_obj.ipv4_addr = str(ip_object)
            else:
                host_obj.ipv6_addr = str(ip_object)
            host_id = host_obj.id
            ret_arr.append(host_obj)

            # Emit a Domain record when naabu resolved a hostname different from the IP
            if host and host != ip:
                domain_obj = data_model.Domain(parent_id=host_id)
                domain_obj.collection_tool_instance_id = tool_instance_id
                domain_obj.name = host
                ret_arr.append(domain_obj)

            port_obj = data_model.Port(parent_id=host_id, id=port_id)
            port_obj.collection_tool_instance_id = tool_instance_id
            port_obj.proto = 0  # TCP
            port_obj.port = port_str
            if tls:
                port_obj.secure = True
            port_id = port_obj.id
            ret_arr.append(port_obj)

            # Build WebComponent records from service / product information.
            # The 'name' field represents the protocol/service (e.g. "http", "ssh")
            # and the 'product' field is the specific technology (e.g. "Apache httpd").
            # Emit a generic component for the service name and, when a distinct
            # product is present, a second specific component with the CPE.
            service_name: str = entry.get('name', '').lower().strip()
            product: str = entry.get('product', '').lower().strip()
            version: str = entry.get('version', '')
            cpes_raw: List[str] = entry.get('cpes', [])

            # Generic service-level component (e.g. "http")
            if service_name and service_name != 'unknown':
                svc_comp = data_model.WebComponent(parent_id=port_id)
                svc_comp.collection_tool_instance_id = tool_instance_id
                svc_comp.name = service_name
                svc_comp.cpe = 'cpe:2.3:a:*:%s:*:*:*:*:*:*:*:*' % service_name
                ret_arr.append(svc_comp)

            # Specific product component (e.g. "apache httpd") — only when it
            # differs from the service name so we don't create a duplicate.
            if product and product != 'unknown' and product != service_name:
                prod_comp = data_model.WebComponent(parent_id=port_id)
                prod_comp.collection_tool_instance_id = tool_instance_id
                prod_comp.name = product
                if version:
                    prod_comp.version = version.lower()
                if cpes_raw:
                    prod_comp.cpe = _cpe22_to_cpe23(cpes_raw[0])
                else:
                    prod_comp.cpe = 'cpe:2.3:a:*:%s:*:*:*:*:*:*:*:*' % product
                ret_arr.append(prod_comp)

    return ret_arr
