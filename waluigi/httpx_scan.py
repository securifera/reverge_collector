from datetime import datetime
from functools import partial
import json
import os
import luigi
import hashlib
import binascii
import base64
import netaddr
import time
import logging

from luigi.util import inherits
from waluigi import scan_utils
from waluigi import data_model
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class Httpx(data_model.WaluigiTool):

    def __init__(self):
        self.name = 'httpx'
        self.collector_type = data_model.CollectorType.ACTIVE.value
        self.scan_order = 4
        self.args = "-favicon -td -t 50 -timeout 3 -maxhr 5 -rstr 10000"
        self.scan_func = Httpx.httpx_scan_func
        self.import_func = Httpx.httpx_import

    @staticmethod
    def httpx_scan_func(scan_input):
        luigi_run_result = luigi.build([HttpXScan(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True

    @staticmethod
    def httpx_import(scan_input):
        luigi_run_result = luigi.build([ImportHttpXOutput(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


class HttpXScan(luigi.Task):

    scan_input = luigi.Parameter()

    def output(self):

        scheduled_scan_obj = self.scan_input
        scan_id = scheduled_scan_obj.id

        # Init directory
        tool_name = scheduled_scan_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)

        # path to input file
        http_outputs_file = dir_path + os.path.sep + "httpx_outputs_" + scan_id
        return luigi.LocalTarget(http_outputs_file)

    def run(self):

        scheduled_scan_obj = self.scan_input

        # Get output file path
        output_file_path = self.output().path
        output_dir = os.path.dirname(output_file_path)

        output_file_list = []

        scope_obj = scheduled_scan_obj.scan_data
        port_target_list_map = {}

        script_args = scheduled_scan_obj.current_tool.args
        if script_args:
            script_args = script_args.split(" ")

        host_list = scope_obj.get_hosts(
            [data_model.RecordTag.SCOPE.value, data_model.RecordTag.LOCAL.value])
        domain_list = scope_obj.get_domains(
            [data_model.RecordTag.SCOPE.value, data_model.RecordTag.LOCAL.value])
        port_list = scope_obj.get_ports(
            [data_model.RecordTag.SCOPE.value, data_model.RecordTag.LOCAL.value])

        # Check if massscan was already run
        mass_scan_ran = False
        for collection_tool in scheduled_scan_obj.collection_tool_map.values():
            if collection_tool.collection_tool.name == 'masscan':
                mass_scan_ran = True
                break

        if mass_scan_ran:
            # Create scan jobs for each port and only scan the IPs mapped to that port
            target_map = scheduled_scan_obj.scan_data.host_port_obj_map
            for target_key in target_map:

                target_obj_dict = target_map[target_key]
                port_obj = target_obj_dict['port_obj']
                port_str = port_obj.port

                host_obj = target_obj_dict['host_obj']
                ip_addr = host_obj.ipv4_addr

                # Add to ip set
                if port_str in port_target_list_map:
                    ip_set = port_target_list_map[port_str]
                else:
                    ip_set = set()
                    port_target_list_map[port_str] = ip_set

                # Add IP to list
                ip_set.add(ip_addr)

        else:

            url_list = scope_obj.get_scope_urls()
            if len(url_list) > 0:

                for url_inst in url_list:

                    port_str = scan_utils.get_url_port(url_inst)
                    if port_str is None:
                        continue

                    port_str = str(port_str)
                    # Add to ip set
                    if port_str in port_target_list_map:
                        endpoint_url_set = port_target_list_map[port_str]
                    else:
                        endpoint_url_set = set()
                        port_target_list_map[port_str] = endpoint_url_set

                    # Add IP to list
                    endpoint_url_set.add(url_inst)

            scan_port_list = scope_obj.get_port_number_list_from_scope()
            if len(scan_port_list) > 0:

                url_list = scope_obj.get_scope_urls()
                for port_str in scan_port_list:

                    # Add a port entry for each host
                    for host_obj in host_list:
                        ip_addr = host_obj.ipv4_addr

                        # Add to ip set
                        if port_str in port_target_list_map:
                            ip_set = port_target_list_map[port_str]
                        else:
                            ip_set = set()
                            port_target_list_map[port_str] = ip_set

                        # Add IP to list
                        ip_set.add(ip_addr)

                    # Add a port entry for each domain
                    for domain_obj in domain_list:
                        # domain_obj = domain_map[domain_id]
                        domain_name = domain_obj.name

                        if port_str in port_target_list_map:
                            ip_set = port_target_list_map[port_str]
                        else:
                            ip_set = set()
                            port_target_list_map[port_str] = ip_set

                        # Add domain to list
                        ip_set.add(domain_name)

            elif len(port_list) > 0:

                for port_obj in port_list:
                    port_str = str(port_obj.port)

                    if port_obj.parent:
                        host_id = port_obj.parent.id
                        if host_id in scope_obj.host_map:
                            host_obj = scope_obj.host_map[host_id]
                            ip_addr = host_obj.ipv4_addr

                            # Add to ip set
                            if port_str in port_target_list_map:
                                ip_set = port_target_list_map[port_str]
                            else:
                                ip_set = set()
                                port_target_list_map[port_str] = ip_set

                            # Add IP to list
                            ip_set.add(ip_addr)

                            # Get domains
                            if host_id in scope_obj.domain_host_id_map:
                                temp_domain_list = scope_obj.domain_host_id_map[host_id]
                                for domain_obj in temp_domain_list:

                                    domain_name = domain_obj.name
                                    ip_set.add(domain_name)

        futures = []
        for port_str in port_target_list_map:

            # Split the input into chunks or httpx will run out of memory
            # and crash the collector
            ip_list = list(port_target_list_map[port_str])
            chunk_size = 100
            num_chunks = (len(ip_list) + chunk_size - 1) // chunk_size

            logger.debug("Splitting %s IPs into %s chunks" %
                         (len(ip_list), num_chunks))
            for chunk_idx in range(num_chunks):
                chunk = ip_list[chunk_idx *
                                chunk_size: (chunk_idx + 1) * chunk_size]

                scan_output_file_path = (
                    output_dir + os.path.sep +
                    f"httpx_out_{port_str}_{chunk_idx}"
                )
                output_file_list.append(scan_output_file_path)

                # Write ips to file
                scan_input_file_path = (
                    output_dir + os.path.sep +
                    f"httpx_in_{port_str}_{chunk_idx}"
                )
                with open(scan_input_file_path, 'w') as file_fd:
                    for ip in chunk:
                        file_fd.write(ip + "\n")

                command = []
                if os.name != 'nt':
                    command.append("sudo")

                command_arr = [
                    "httpx",
                    "-json",
                    "-silent",
                    "-irr",  # Return response so Headers can be parsed
                    # "-ss", Removed from default because it is too memory/cpu intensive for small collectors
                    "-s",  # Stream mode
                    "-sd",  # Disable dedupe
                    "-fhr",
                    "-nf",
                    "-l",
                    scan_input_file_path,
                    "-p",
                    port_str,
                    "-o",
                    scan_output_file_path
                ]

                command.extend(command_arr)

                # Add script args
                if script_args and len(script_args) > 0:
                    command.extend(script_args)

                callback_with_tool_id = partial(
                    scheduled_scan_obj.register_tool_executor, scheduled_scan_obj.current_tool_instance_id)

                # Add process dict to process array
                futures.append(scan_utils.executor.submit(
                    scan_utils.process_wrapper, cmd_args=command, pid_callback=callback_with_tool_id))

        # Register futures
        scan_proc_inst = data_model.ToolExecutor(futures)
        scheduled_scan_obj.register_tool_executor(
            scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

        # Wait for the tasks to complete and retrieve results
        for future in futures:
            future.result()  # This blocks until the individual task is complete

        results_dict = {  # 'port_to_id_map': port_to_id_map,
            'output_file_list': output_file_list}

        # Write output file
        with open(output_file_path, 'w') as file_fd:
            file_fd.write(json.dumps(results_dict))


@inherits(HttpXScan)
class ImportHttpXOutput(data_model.ImportToolXOutput):

    def requires(self):
        # Requires HttpScan Task to be run prior
        return HttpXScan(scan_input=self.scan_input)

    def run(self):

        scheduled_scan_obj = self.scan_input

        http_output_file = self.input().path
        with open(http_output_file, 'r') as file_fd:
            data = file_fd.read()

        if len(data) == 0:
            logger.error("Httpx scan output file is empty")
            return

        hash_alg = hashlib.sha1
        scan_data_dict = json.loads(data)

        # Get data and map
        ret_arr = []
        output_file_list = scan_data_dict['output_file_list']

        path_hash_map = {}
        screenshot_hash_map = {}

        for output_file in output_file_list:

            obj_arr = scan_utils.parse_json_blob_file(output_file)
            for httpx_scan in obj_arr:

                # Attempt to get the port id
                target_str = httpx_scan['input']
                port_str = httpx_scan['port']

                host_id = None
                port_id = None
                host_key = '%s:%s' % (target_str, port_str)

                # See if we have an host/port mapping already for this ip and port
                if host_key in scheduled_scan_obj.scan_data.host_port_obj_map:
                    host_port_dict = scheduled_scan_obj.scan_data.host_port_obj_map[host_key]
                    port_id = host_port_dict['port_obj'].id
                    host_id = host_port_dict['host_obj'].id
                elif target_str in scheduled_scan_obj.scan_data.host_ip_id_map:
                    host_id = scheduled_scan_obj.scan_data.host_ip_id_map[target_str]

                ip_str = None
                if 'host' in httpx_scan:
                    ip_str = httpx_scan['host']
                elif 'a' in httpx_scan:
                    ip_str = httpx_scan['a'][0]

                # If we have an IP somewhere in the scan
                if ip_str:
                    ip_object = netaddr.IPAddress(ip_str)

                    # Create Host object
                    host_obj = data_model.Host(id=host_id)

                    ip_object = netaddr.IPAddress(ip_str)
                    if ip_object.version == 4:
                        host_obj.ipv4_addr = str(ip_object)
                    elif ip_object.version == 6:
                        host_obj.ipv6_addr = str(ip_object)

                    host_id = host_obj.id

                    # Add host
                    ret_arr.append(host_obj)

                # Create Port object
                port_obj = data_model.Port(
                    parent_id=host_id, id=port_id)
                port_obj.proto = 0
                port_obj.port = port_str
                port_id = port_obj.id

                # If TLS
                if 'scheme' in httpx_scan and httpx_scan['scheme'] == "https":
                    port_obj.secure = True

                # Set data
                title = None
                if 'title' in httpx_scan:
                    title = httpx_scan['title']

                status_code = None
                if 'status_code' in httpx_scan:
                    try:
                        status_code = int(httpx_scan['status_code'])
                    except:
                        status_code = None

                # Add secure flag if a 400 was returned and it has a certain title
                if (status_code and status_code == 400) and (title and 'The plain HTTP request was sent to HTTPS port' in title):
                    port_obj.secure = True

                # Add port
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
                        except:
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
                    path_hash = hashobj.digest()
                    hex_str = binascii.hexlify(path_hash).decode()
                    web_path_hash = hex_str

                    # Attach the favicon to the root path
                    if tmp_fav_hash and web_path == "/":
                        favicon_hash = tmp_fav_hash

                    if web_path_hash in path_hash_map:
                        path_obj = path_hash_map[web_path_hash]
                    else:
                        path_obj = data_model.ListItem()
                        path_obj.web_path = web_path
                        path_obj.web_path_hash = web_path_hash

                        # Add to map and the object list
                        path_hash_map[web_path_hash] = path_obj
                        ret_arr.append(path_obj)

                    web_path_id = path_obj.id

                screenshot_id = None
                if 'screenshot_bytes' in httpx_scan:
                    screenshot_bytes_b64 = httpx_scan['screenshot_bytes']
                    ss_data = base64.b64decode(screenshot_bytes_b64)
                    hashobj = hash_alg()
                    hashobj.update(ss_data)
                    image_hash = hashobj.digest()
                    image_hash_str = binascii.hexlify(image_hash).decode()

                    if image_hash_str in screenshot_hash_map:
                        screenshot_obj = screenshot_hash_map[image_hash_str]
                    else:
                        screenshot_obj = data_model.Screenshot()
                        screenshot_obj.data = screenshot_bytes_b64
                        screenshot_obj.data_hash = image_hash_str

                        # Add to map and the object list
                        screenshot_hash_map[image_hash_str] = screenshot_obj
                        ret_arr.append(screenshot_obj)

                    screenshot_id = screenshot_obj.id

                domain_used = None
                if 'url' in httpx_scan:
                    url = httpx_scan['url'].lower()
                    u = urlparse(url)
                    host = u.netloc
                    if ":" in host:
                        domain_used = host.split(":")[0]

                # Add domains
                cert_obj = None
                if 'tls' in httpx_scan:
                    tls_data = httpx_scan['tls']

                    # Create a certificate object
                    cert_obj = data_model.Certificate(
                        parent_id=port_obj.id)

                    if 'subject_an' in tls_data:
                        dns_names = tls_data['subject_an']
                        for dns_name in dns_names:
                            domain_obj = cert_obj.add_domain(host_id, dns_name)
                            if domain_obj:
                                ret_arr.append(domain_obj)

                    if 'host' in tls_data:
                        common_name = tls_data['host']
                        if type(common_name) == list:
                            for common_name_inst in common_name:
                                domain_obj = cert_obj.add_domain(host_id,
                                                                 common_name_inst)
                                if domain_obj:
                                    ret_arr.append(domain_obj)
                        else:
                            domain_obj = cert_obj.add_domain(
                                host_id, common_name)
                            if domain_obj:
                                ret_arr.append(domain_obj)

                    if 'subject_cn' in tls_data:
                        common_name = tls_data['subject_cn']
                        if type(common_name) == list:
                            for common_name_inst in common_name:
                                domain_obj = cert_obj.add_domain(host_id,
                                                                 common_name_inst)
                                if domain_obj:
                                    ret_arr.append(domain_obj)

                        else:
                            domain_obj = cert_obj.add_domain(
                                host_id, common_name)
                            if domain_obj:
                                ret_arr.append(domain_obj)

                    if 'issuer_dn' in tls_data:
                        issuer = tls_data['issuer_dn']
                        cert_obj.issuer = issuer

                    if 'not_before' in tls_data:
                        issued = tls_data['not_before']
                        # Parse the time string into a datetime object in UTC
                        dt = datetime.strptime(issued, '%Y-%m-%dT%H:%M:%SZ')
                        cert_obj.issued = int(time.mktime(dt.timetuple()))

                    if 'not_after' in tls_data:
                        expires = tls_data['not_after']
                        dt = datetime.strptime(expires, '%Y-%m-%dT%H:%M:%SZ')
                        cert_obj.expires = int(time.mktime(dt.timetuple()))

                    if 'fingerprint_hash' in tls_data:
                        cert_hash_map = tls_data['fingerprint_hash']
                        if 'sha1' in cert_hash_map:
                            sha_cert_hash = cert_hash_map['sha1']
                            cert_obj.fingerprint_hash = sha_cert_hash

                    # Add the cert object
                    ret_arr.append(cert_obj)

                endpoint_domain_id = None
                if cert_obj and domain_used in cert_obj.domain_name_id_map:
                    # logger.debug("Found domain in cert: %s" % domain_used)
                    endpoint_domain_id = cert_obj.domain_name_id_map[domain_used]

                # Add http component
                component_obj = data_model.WebComponent(
                    parent_id=port_obj.id)
                component_obj.name = 'http'
                ret_arr.append(component_obj)

                if 'tech' in httpx_scan:
                    tech_list = httpx_scan['tech']
                    for tech_entry in tech_list:

                        component_obj = data_model.WebComponent(
                            parent_id=port_obj.id)

                        if ":" in tech_entry:
                            tech_entry_arr = tech_entry.split(":")
                            component_obj.name = tech_entry_arr[0]
                            component_obj.version = tech_entry_arr[1]
                        else:
                            component_obj.name = tech_entry

                        ret_arr.append(component_obj)

                # Add http endpoint
                http_endpoint_obj = data_model.HttpEndpoint(
                    parent_id=port_obj.id)
                http_endpoint_obj.web_path_id = web_path_id

                # Add the endpoint
                ret_arr.append(http_endpoint_obj)

                http_endpoint_data_obj = data_model.HttpEndpointData(
                    parent_id=http_endpoint_obj.id)
                http_endpoint_data_obj.domain_id = endpoint_domain_id
                http_endpoint_data_obj.title = title
                http_endpoint_data_obj.status = status_code
                http_endpoint_data_obj.last_modified = last_modified
                http_endpoint_data_obj.screenshot_id = screenshot_id
                http_endpoint_data_obj.fav_icon_hash = favicon_hash

                # Add the endpoint data
                ret_arr.append(http_endpoint_data_obj)

        # Import, Update, & Save
        self.import_results(scheduled_scan_obj, ret_arr)
