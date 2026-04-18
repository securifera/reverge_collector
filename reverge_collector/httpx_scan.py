"""
HTTPX web scanning module for the reverge_collector framework.

This module provides comprehensive HTTP/HTTPS scanning capabilities using HTTPX,
a fast and multi-purpose HTTP toolkit. It performs web application discovery,
technology detection, certificate analysis, and screenshot capture for web assets.

The module implements both scanning and data import functionality through Luigi tasks,
supporting parallel HTTP probing and comprehensive web asset enumeration.

Classes:
    Httpx: Tool configuration class for HTTPX scanner  
    HttpXScan: Luigi task for executing HTTPX web scans
    ImportHttpXOutput: Luigi task for processing and importing HTTPX scan results

"""

from datetime import datetime
from functools import partial
import json
import os
from typing import Dict, Any, List, Set, Optional, Union
import hashlib
import binascii
import base64
import netaddr
import time
import logging

from reverge_collector import scan_utils
from reverge_collector import data_model
from reverge_collector.proc_utils import process_wrapper
from urllib.parse import urlparse
from reverge_collector.tool_spec import ToolSpec


class Httpx(ToolSpec):

    name = 'httpx'
    description = 'HTTPX is a fast and multi-purpose HTTP toolkit that allows you to run multiple requests in parallel.'
    project_url = 'https://github.com/projectdiscovery/httpx'
    tags = ['http-crawl', 'service-detection', 'fast']
    collector_type = data_model.CollectorType.ACTIVE.value
    scan_order = 4
    args = '-favicon -td -t 50 -timeout 3 -maxhr 5 -rstr 10000 -tls-grab'
    input_records = [
        data_model.ServerRecordType.HOST,
        data_model.ServerRecordType.PORT,
        data_model.ServerRecordType.DOMAIN,
        data_model.ServerRecordType.HTTP_ENDPOINT_DATA,
        data_model.ServerRecordType.SUBNET,
    ]
    output_records = [
        data_model.ServerRecordType.HTTP_ENDPOINT_DATA,
        data_model.ServerRecordType.HTTP_ENDPOINT,
        data_model.ServerRecordType.COLLECTION_MODULE,
        data_model.ServerRecordType.COLLECTION_MODULE_OUTPUT,
        data_model.ServerRecordType.WEB_COMPONENT,
        data_model.ServerRecordType.DOMAIN,
        data_model.ServerRecordType.CERTIFICATE,
        data_model.ServerRecordType.SCREENSHOT,
        data_model.ServerRecordType.LIST_ITEM,
        data_model.ServerRecordType.PORT,
        data_model.ServerRecordType.HOST,
    ]

    def execute_scan(self, scan_input) -> None:
        execute_scan(scan_input)

    def parse_output(self, output_path: str, scan_input) -> list:
        with open(output_path, 'r') as f:
            data = f.read()
        if not data:
            return []
        scan_data_dict = json.loads(data)
        output_file_list = scan_data_dict['output_file_list']
        return parse_httpx_output(
            output_file_list,
            scan_input.current_tool_instance_id,
            scan_input.current_tool.id,
            scan_input.scan_data,
        )


def get_output_path(scan_input) -> str:
    scan_id: str = scan_input.id
    tool_name: str = scan_input.current_tool.name
    dir_path: str = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)
    return dir_path + os.path.sep + "httpx_outputs_" + scan_id


def execute_scan(scan_input) -> None:
    output_file_path = get_output_path(scan_input)
    if os.path.exists(output_file_path):
        return

    scheduled_scan_obj = scan_input
    output_dir = os.path.dirname(output_file_path)

    output_file_list = []
    scope_obj = scheduled_scan_obj.scan_data
    port_target_list_map = {}

    script_args = scheduled_scan_obj.current_tool.args
    if script_args:
        script_args = script_args.split(" ")

    scope_urls = scheduled_scan_obj.scan_data.get_url_metadata_map()

    host_list = scope_obj.get_hosts(
        [data_model.RecordTag.SCOPE.value, data_model.RecordTag.LOCAL.value])
    domain_list = scope_obj.get_domains(
        [data_model.RecordTag.SCOPE.value, data_model.RecordTag.LOCAL.value])
    port_list = scope_obj.get_ports(
        [data_model.RecordTag.SCOPE.value, data_model.RecordTag.LOCAL.value])

    mass_scan_ran = False
    for collection_tool in scheduled_scan_obj.collection_tool_map.values():
        if collection_tool.collection_tool.name == 'masscan':
            mass_scan_ran = True
            break

    if mass_scan_ran:
        for url_str in scope_urls.keys():
            port_str = scan_utils.get_url_port(url_str)
            if port_str is None:
                continue
            port_str = str(port_str)
            if port_str in port_target_list_map:
                url_set = port_target_list_map[port_str]
            else:
                url_set = set()
                port_target_list_map[port_str] = url_set
            url_set.add(url_str)
    else:
        url_list = scope_obj.get_scope_urls()
        if len(url_list) > 0:
            for url_inst in url_list:
                port_str = scan_utils.get_url_port(url_inst)
                if port_str is None:
                    continue
                port_str = str(port_str)
                if port_str in port_target_list_map:
                    endpoint_url_set = port_target_list_map[port_str]
                else:
                    endpoint_url_set = set()
                    port_target_list_map[port_str] = endpoint_url_set
                endpoint_url_set.add(url_inst)

        scan_port_list = scope_obj.get_port_number_list_from_scope()
        if len(scan_port_list) > 0:
            for port_str in scan_port_list:
                for host_obj in host_list:
                    ip_addr = host_obj.ipv4_addr
                    if port_str in port_target_list_map:
                        ip_set = port_target_list_map[port_str]
                    else:
                        ip_set = set()
                        port_target_list_map[port_str] = ip_set
                    ip_set.add(ip_addr)
                for domain_obj in domain_list:
                    domain_name = domain_obj.name
                    if port_str in port_target_list_map:
                        ip_set = port_target_list_map[port_str]
                    else:
                        ip_set = set()
                        port_target_list_map[port_str] = ip_set
                    ip_set.add(domain_name)
        elif len(port_list) > 0:
            for port_obj in port_list:
                url_list = port_obj.get_url_list(scope_obj)
                port_str = str(port_obj.port)
                if port_str in port_target_list_map:
                    ip_set = port_target_list_map[port_str]
                else:
                    ip_set = set()
                    port_target_list_map[port_str] = ip_set
                ip_set.update(url_list)

    futures = []
    for port_str in port_target_list_map:
        scan_output_file_path = output_dir + os.path.sep + "httpx_out_" + port_str
        output_file_list.append(scan_output_file_path)

        ip_list = port_target_list_map[port_str]
        scan_input_file_path = output_dir + os.path.sep + "httpx_in_" + port_str
        with open(scan_input_file_path, 'w') as file_fd:
            for ip in ip_list:
                file_fd.write(ip + "\n")

        command = []
        if os.name != 'nt':
            command.append("sudo")

        command_arr = [
            "/usr/local/bin/httpx",
            "-json",
            "-silent",
            "-irr",
            "-s",
            "-sd",
            "-l",
            scan_input_file_path,
            "-o",
            scan_output_file_path
        ]
        command.extend(command_arr)

        if script_args and len(script_args) > 0:
            command.extend(script_args)

        callback_with_tool_id = partial(
            scheduled_scan_obj.register_tool_executor, scheduled_scan_obj.current_tool_instance_id)

        futures.append(scan_utils.executor.submit(
            process_wrapper, cmd_args=command, pid_callback=callback_with_tool_id))

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
                    "HTTPX scan for scan ID %s exited with code %d: %s" % (scheduled_scan_obj.id, exit_code, err_msg))
                raise RuntimeError("HTTPX scan for scan ID %s exited with code %d: %s" % (
                    scheduled_scan_obj.id, exit_code, err_msg))

    results_dict = {'output_file_list': output_file_list}
    with open(output_file_path, 'w') as file_fd:
        file_fd.write(json.dumps(results_dict))


def parse_httpx_output(
    output_file_list: List[str],
    tool_instance_id: Optional[str] = None,
    tool_id: Optional[str] = None,
    scope_obj: Optional[Any] = None,
) -> List[Any]:
    """Parse httpx JSON output files and return data_model Record objects.

    Args:
        output_file_list: List of paths to httpx JSON output files.
        tool_instance_id: Value for ``collection_tool_instance_id`` on each record.
        tool_id:          Parent tool ID for CollectionModule records.
        scope_obj:        Optional scan data for correlating IDs with existing
                          records.  When ``None`` every record receives a fresh UUID.

    Returns:
        List of data_model Record objects.
    """
    hash_alg = hashlib.sha1
    ret_arr: List[Any] = []
    path_hash_map: Dict[str, Any] = {}
    screenshot_hash_map: Dict[str, Any] = {}
    cert_map: Dict[str, Any] = {}

    for output_file in output_file_list:

        obj_arr = scan_utils.parse_json_blob_file(output_file)
        for httpx_scan in obj_arr:

            target_str = httpx_scan['input']
            port_str = httpx_scan['port']

            host_id = None
            host_key = '%s:%s' % (target_str, port_str)

            if scope_obj is not None:
                if host_key in scope_obj.host_port_obj_map:
                    host_port_dict = scope_obj.host_port_obj_map[host_key]
                    host_id = host_port_dict['host_obj'].id
                elif target_str in scope_obj.host_ip_id_map:
                    host_id = scope_obj.host_ip_id_map[target_str]

            ip_str = None
            if 'host_ip' in httpx_scan:
                ip_str = httpx_scan['host_ip']
            elif 'a' in httpx_scan:
                ip_str = httpx_scan['a'][0]

            if ip_str:
                ip_object = netaddr.IPAddress(ip_str)
                host_obj = data_model.Host()
                host_obj.collection_tool_instance_id = tool_instance_id
                if ip_object.version == 4:
                    host_obj.ipv4_addr = str(ip_object)
                elif ip_object.version == 6:
                    host_obj.ipv6_addr = str(ip_object)
                host_id = host_obj.id
                ret_arr.append(host_obj)

            if 'cname' in httpx_scan:
                cname = httpx_scan['cname']
                if type(cname) == list:
                    for cname_inst in cname:
                        domain_obj = data_model.Domain(parent_id=host_id)
                        domain_obj.collection_tool_instance_id = tool_instance_id
                        domain_obj.name = cname_inst
                        ret_arr.append(domain_obj)

            port_obj = data_model.Port(parent_id=host_id)
            port_obj.collection_tool_instance_id = tool_instance_id
            port_obj.proto = 0
            port_obj.port = port_str

            if 'scheme' in httpx_scan and httpx_scan['scheme'] == "https":
                port_obj.secure = True

            title = None
            if 'title' in httpx_scan:
                title = httpx_scan['title']

            status_code = None
            if 'status_code' in httpx_scan:
                try:
                    status_code = int(httpx_scan['status_code'])
                except Exception:
                    status_code = None

            content_length = None
            if 'content_length' in httpx_scan:
                try:
                    content_length = int(httpx_scan['content_length'])
                except Exception:
                    content_length = None

            if (status_code and status_code == 400) and (
                    title and 'The plain HTTP request was sent to HTTPS port' in title):
                port_obj.secure = True

            ret_arr.append(port_obj)

            last_modified = None
            if 'header' in httpx_scan:
                header_dict = httpx_scan['header']
                if 'last_modified' in header_dict:
                    last_modified_str = header_dict['last_modified']
                    try:
                        timestamp_datetime = datetime.strptime(
                            last_modified_str, "%A, %d-%b-%Y %H:%M:%S GMT")
                        last_modified = int(time.mktime(
                            timestamp_datetime.timetuple()))
                    except Exception:
                        pass

            favicon_hash = None
            tmp_fav_hash = None
            if 'favicon' in httpx_scan:
                favicon_hash = httpx_scan['favicon']
                tmp_fav_hash = favicon_hash

            web_path_id = None
            if 'path' in httpx_scan:
                web_path = httpx_scan['path'].strip()
                hashobj = hash_alg()
                hashobj.update(web_path.encode())
                web_path_hash = binascii.hexlify(hashobj.digest()).decode()

                if tmp_fav_hash and web_path == "/":
                    favicon_hash = tmp_fav_hash

                if web_path_hash in path_hash_map:
                    path_obj = path_hash_map[web_path_hash]
                else:
                    path_obj = data_model.ListItem()
                    path_obj.collection_tool_instance_id = tool_instance_id
                    path_obj.web_path = web_path
                    path_obj.web_path_hash = web_path_hash
                    path_hash_map[web_path_hash] = path_obj
                    ret_arr.append(path_obj)
                web_path_id = path_obj.id

            screenshot_id = None
            if 'screenshot_bytes' in httpx_scan:
                screenshot_bytes_b64 = httpx_scan['screenshot_bytes']
                ss_data = base64.b64decode(screenshot_bytes_b64)
                hashobj = hash_alg()
                hashobj.update(ss_data)
                image_hash_str = binascii.hexlify(hashobj.digest()).decode()

                if image_hash_str in screenshot_hash_map:
                    screenshot_obj = screenshot_hash_map[image_hash_str]
                else:
                    screenshot_obj = data_model.Screenshot()
                    screenshot_obj.collection_tool_instance_id = tool_instance_id
                    screenshot_obj.screenshot = screenshot_bytes_b64
                    screenshot_obj.image_hash = image_hash_str
                    screenshot_hash_map[image_hash_str] = screenshot_obj
                    ret_arr.append(screenshot_obj)
                screenshot_id = screenshot_obj.id

            domain_used = None
            if 'url' in httpx_scan:
                u = urlparse(httpx_scan['url'].lower())
                domain_used = u.netloc
                if ":" in domain_used:
                    domain_used = domain_used.split(":")[0]

            cert_obj = None
            if 'tls' in httpx_scan:
                tls_data = httpx_scan['tls']
                new_cert = True
                if 'fingerprint_hash' in tls_data:
                    cert_hash_map = tls_data['fingerprint_hash']
                    if 'sha1' in cert_hash_map:
                        sha_cert_hash = cert_hash_map['sha1']
                        if sha_cert_hash in cert_map:
                            cert_obj = cert_map[sha_cert_hash]
                            new_cert = False
                        else:
                            cert_obj = data_model.Certificate(
                                parent_id=port_obj.id)
                            cert_obj.collection_tool_instance_id = tool_instance_id
                            cert_obj.fingerprint_hash = sha_cert_hash
                            cert_map[sha_cert_hash] = cert_obj

                if new_cert:
                    if 'subject_an' in tls_data:
                        for dns_name in tls_data['subject_an']:
                            domain_obj = cert_obj.add_domain(
                                host_id, dns_name, tool_instance_id)
                            if domain_obj:
                                ret_arr.append(domain_obj)

                    if 'host' in tls_data:
                        common_name = tls_data['host']
                        if type(common_name) == list:
                            for common_name_inst in common_name:
                                domain_obj = cert_obj.add_domain(
                                    host_id, common_name_inst, tool_instance_id)
                                if domain_obj:
                                    ret_arr.append(domain_obj)
                        else:
                            domain_obj = cert_obj.add_domain(
                                host_id, common_name, tool_instance_id)
                            if domain_obj:
                                ret_arr.append(domain_obj)

                    if 'subject_cn' in tls_data:
                        common_name = tls_data['subject_cn']
                        if type(common_name) == list:
                            for common_name_inst in common_name:
                                domain_obj = cert_obj.add_domain(
                                    host_id, common_name_inst, tool_instance_id)
                                if domain_obj:
                                    ret_arr.append(domain_obj)
                        else:
                            domain_obj = cert_obj.add_domain(
                                host_id, common_name, tool_instance_id)
                            if domain_obj:
                                ret_arr.append(domain_obj)

                    if 'issuer_dn' in tls_data:
                        cert_obj.issuer = tls_data['issuer_dn']

                    if 'not_before' in tls_data:
                        dt = datetime.strptime(
                            tls_data['not_before'], '%Y-%m-%dT%H:%M:%SZ')
                        cert_obj.issued = int(time.mktime(dt.timetuple()))

                    if 'not_after' in tls_data:
                        dt = datetime.strptime(
                            tls_data['not_after'], '%Y-%m-%dT%H:%M:%SZ')
                        cert_obj.expires = int(time.mktime(dt.timetuple()))

                    ret_arr.append(cert_obj)

            endpoint_domain_id = None
            if cert_obj and domain_used in cert_obj.domain_name_id_map:
                endpoint_domain_id = cert_obj.domain_name_id_map[domain_used]

            component_obj = data_model.WebComponent(parent_id=port_obj.id)
            component_obj.collection_tool_instance_id = tool_instance_id
            component_obj.name = 'http'
            ret_arr.append(component_obj)

            if 'tech' in httpx_scan:
                for tech_entry in httpx_scan['tech']:
                    component_obj = data_model.WebComponent(
                        parent_id=port_obj.id)
                    component_obj.collection_tool_instance_id = tool_instance_id
                    if ":" in tech_entry:
                        tech_parts = tech_entry.split(":")
                        component_obj.name = tech_parts[0]
                        component_obj.version = tech_parts[1]
                    else:
                        component_obj.name = tech_entry
                    ret_arr.append(component_obj)

            if 'raw_header' in httpx_scan:
                output = httpx_scan['raw_header']
                if output and len(output) > 0:
                    module_obj = data_model.CollectionModule(parent_id=tool_id)
                    module_obj.collection_tool_instance_id = tool_instance_id
                    module_obj.name = 'http-response-headers'
                    ret_arr.append(module_obj)
                    module_output_obj = data_model.CollectionModuleOutput(
                        parent_id=module_obj.id)
                    module_output_obj.collection_tool_instance_id = tool_instance_id
                    module_output_obj.output = output
                    module_output_obj.port_id = port_obj.id
                    ret_arr.append(module_output_obj)

            if 'body' in httpx_scan:
                output = httpx_scan['body']
                if output and len(output) > 0:
                    module_obj = data_model.CollectionModule(parent_id=tool_id)
                    module_obj.collection_tool_instance_id = tool_instance_id
                    module_obj.name = 'http-response-body'
                    ret_arr.append(module_obj)
                    module_output_obj = data_model.CollectionModuleOutput(
                        parent_id=module_obj.id)
                    module_output_obj.collection_tool_instance_id = tool_instance_id
                    module_output_obj.output = output
                    module_output_obj.port_id = port_obj.id
                    ret_arr.append(module_output_obj)

            http_endpoint_obj = data_model.HttpEndpoint(parent_id=port_obj.id)
            http_endpoint_obj.collection_tool_instance_id = tool_instance_id
            http_endpoint_obj.web_path_id = web_path_id
            ret_arr.append(http_endpoint_obj)

            http_endpoint_data_obj = data_model.HttpEndpointData(
                parent_id=http_endpoint_obj.id)
            http_endpoint_data_obj.collection_tool_instance_id = tool_instance_id
            http_endpoint_data_obj.domain_id = endpoint_domain_id
            http_endpoint_data_obj.title = title
            http_endpoint_data_obj.status = status_code
            http_endpoint_data_obj.last_modified = last_modified
            http_endpoint_data_obj.screenshot_id = screenshot_id
            http_endpoint_data_obj.fav_icon_hash = favicon_hash
            http_endpoint_data_obj.content_length = content_length
            ret_arr.append(http_endpoint_data_obj)

    return ret_arr
