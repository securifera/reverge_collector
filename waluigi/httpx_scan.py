"""
HTTPX web scanning module for the Waluigi framework.

This module provides comprehensive HTTP/HTTPS scanning capabilities using HTTPX,
a fast and multi-purpose HTTP toolkit. It performs web application discovery,
technology detection, certificate analysis, and screenshot capture for web assets.

The module uses the centralized get_urls() method for consistent URL extraction
across the framework, grouping URLs by port for efficient parallel processing.

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
from waluigi.proc_utils import process_wrapper
from urllib.parse import urlparse


class Httpx(data_model.WaluigiTool):
    """
    HTTPX web scanner tool configuration.

    This class configures the HTTPX web scanner for integration with the
    Waluigi framework. HTTPX is a fast and multi-purpose HTTP toolkit that
    enables parallel web application discovery, technology detection, and
    comprehensive web asset enumeration.

    The tool is configured for high-performance scanning with favicon analysis,
    technology detection, TLS certificate grabbing, and response analysis.

    Attributes:
        name (str): Tool identifier name
        description (str): Human-readable tool description
        project_url (str): Official project URL
        collector_type (str): Type of collection (ACTIVE)
        scan_order (int): Execution order in scan chain
        args (str): Default command line arguments
        scan_func (callable): Function to execute scans
        import_func (callable): Function to import results

    Example:
        >>> httpx_tool = Httpx()
        >>> print(httpx_tool.name)
        'httpx'
        >>> httpx_tool.scan_func(scan_input)
        True
    """

    def __init__(self) -> None:
        """
        Initialize HTTPX tool configuration.

        Sets up the tool with default parameters for web scanning including
        favicon analysis, technology detection, parallel processing, and
        TLS certificate analysis.
        """
        self.name: str = 'httpx'
        self.description: str = 'HTTPX is a fast and multi-purpose HTTP toolkit that allows you to run multiple requests in parallel.'
        self.project_url: str = "https://github.com/projectdiscovery/httpx"
        self.collector_type: str = data_model.CollectorType.ACTIVE.value
        self.scan_order: int = 4
        self.args: str = "-favicon -td -t 50 -timeout 3 -maxhr 5 -rstr 10000 -tls-grab"
        self.input_records = [
            data_model.ServerRecordType.HOST,
            data_model.ServerRecordType.PORT,
            data_model.ServerRecordType.DOMAIN,
            data_model.ServerRecordType.HTTP_ENDPOINT_DATA
        ]
        self.output_records = [
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
            data_model.ServerRecordType.HOST
        ]
        self.scan_func = Httpx.httpx_scan_func
        self.import_func = Httpx.httpx_import

    @staticmethod
    def httpx_scan_func(scan_input: data_model.ScheduledScan) -> bool:
        """
        Execute HTTPX web scan.

        Initiates an HTTPX scan using Luigi task orchestration. The scan targets
        web services and applications, probing for HTTP/HTTPS endpoints with
        comprehensive analysis including technology detection and certificate
        information.

        Args:
            scan_input (data_model.ScheduledScan): Scheduled scan configuration
                containing target information and scan parameters

        Returns:
            bool: True if scan completed successfully, False otherwise

        Example:
            >>> scan_input = ScheduledScan(...)
            >>> success = Httpx.httpx_scan_func(scan_input)
            >>> print(success)
            True
        """
        luigi_run_result = luigi.build([HttpXScan(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True

    @staticmethod
    def httpx_import(scan_input: data_model.ScheduledScan) -> bool:
        """
        Import and process HTTPX scan results.

        Processes the JSON output from completed HTTPX scans, parsing web
        application information, SSL certificates, technology stacks, and
        HTTP endpoint data into the data model.

        Args:
            scan_input (data_model.ScheduledScan): Scheduled scan configuration
                containing scan results to import

        Returns:
            bool: True if import completed successfully, False otherwise

        Example:
            >>> scan_input = ScheduledScan(...)
            >>> success = Httpx.httpx_import(scan_input)
            >>> print(success)
            True
        """
        luigi_run_result = luigi.build([ImportHttpXOutput(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


class HttpXScan(luigi.Task):
    """
    Luigi task for executing HTTPX web scans.

    This task orchestrates the execution of HTTPX scans against web endpoints,
    handling target preparation, parallel scanning, and output collection. The
    task supports both masscan-optimized scanning and comprehensive web discovery
    across hosts, domains, and ports.

    The scan process includes:
    - URL extraction using scan_data.get_urls() when masscan results are available
    - Port-based URL grouping for optimized parallel scanning
    - Fallback to traditional host/domain/port enumeration when no masscan data
    - Parallel HTTPX execution for performance
    - JSON output collection for import processing

    Features:
    - Technology detection and favicon analysis
    - SSL/TLS certificate analysis
    - HTTP response header analysis
    - Screenshot capture capabilities
    - Response size and timeout controls

    Attributes:
        scan_input (luigi.Parameter): Scheduled scan configuration parameter

    Example:
        >>> scan_task = HttpXScan(scan_input=scheduled_scan)
        >>> scan_task.run()
        # Executes HTTPX scan and saves JSON results
    """

    scan_input: luigi.Parameter = luigi.Parameter()

    def output(self) -> luigi.LocalTarget:
        """
        Define output file target for scan results.

        Creates the output file path where scan results metadata will be stored,
        incorporating scan ID for uniqueness.

        Returns:
            luigi.LocalTarget: Output file target for scan results metadata

        Example:
            >>> task = HttpXScan(scan_input=scan)
            >>> target = task.output()
            >>> print(target.path)
            '/path/to/outputs/httpx_outputs_scan123'
        """
        scheduled_scan_obj = self.scan_input
        scan_id: str = scheduled_scan_obj.id

        # Init directory
        tool_name: str = scheduled_scan_obj.current_tool.name
        dir_path: str = scan_utils.init_tool_folder(
            tool_name, 'outputs', scan_id)

        # Path to output metadata file
        http_outputs_file: str = dir_path + os.path.sep + "httpx_outputs_" + scan_id
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

        # Use get_urls() to get all URLs and group them by port for HTTPX parallel processing
        scope_urls = scheduled_scan_obj.scan_data.get_urls()

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
            # Use get_urls() for masscan optimization - group URLs by port for parallel processing
            for url_str in scope_urls.keys():
                # Extract port from URL for grouping
                port_str = scan_utils.get_url_port(url_str)
                if port_str is None:
                    continue

                port_str = str(port_str)

                # Add to port-based grouping
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

                    url_list = port_obj.get_urls(scope_obj)
                    # Add to ip set
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

            # Write ips to file
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
                "-irr",  # Return response so Headers can be parsed
                # "-ss", Removed from default because it is too memory/cpu intensive for small collectors
                "-s",  # Stream mode
                "-sd",  # Disable dedupe
                "-l",
                scan_input_file_path,
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
                process_wrapper, cmd_args=command, pid_callback=callback_with_tool_id))

        # Register futures
        scan_proc_inst = data_model.ToolExecutor(futures)
        scheduled_scan_obj.register_tool_executor(
            scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

        # Wait for the tasks to complete and retrieve results
        for future in futures:
            ret_dict = future.result()  # This blocks until the individual task is complete
            if ret_dict and 'exit_code' in ret_dict:
                exit_code = ret_dict['exit_code']
                if exit_code != 0:
                    err_msg = ''
                    if 'stderr' in ret_dict and ret_dict['stderr']:
                        err_msg = ret_dict['stderr']
                    logging.getLogger(__name__).error(
                        "Nuclei scan for scan ID %s exited with code %d: %s" % (scheduled_scan_obj.id, exit_code, err_msg))
                    raise RuntimeError("Nuclei scan for scan ID %s exited with code %d: %s" % (
                        scheduled_scan_obj.id, exit_code, err_msg))

        results_dict = {'output_file_list': output_file_list}

        # Write output file
        with open(output_file_path, 'w') as file_fd:
            file_fd.write(json.dumps(results_dict))


@inherits(HttpXScan)
class ImportHttpXOutput(data_model.ImportToolXOutput):
    """
    Luigi task for importing and processing HTTPX scan results.

    This task processes the JSON output from HTTPX scans, parsing comprehensive
    web application information including HTTP endpoints, SSL certificates,
    technology stacks, screenshots, and response data into the data model.

    The import process extracts:
    - Host information and IP address resolution
    - HTTP/HTTPS endpoint data with status codes and titles
    - SSL/TLS certificates with validity and domain information
    - Web technologies and component versions
    - Favicon hashes and screenshot data
    - HTTP response headers and metadata
    - Web paths and endpoint relationships

    Attributes:
        Inherits all attributes from HttpXScan task

    Example:
        >>> import_task = ImportHttpXOutput(scan_input=scheduled_scan)
        >>> import_task.run()
        # Processes and imports HTTPX web application results
    """

    def requires(self) -> HttpXScan:
        """
        Specify task dependencies.

        This task requires the HttpXScan task to complete before it can
        process the JSON scan results.

        Returns:
            HttpXScan: The required scan task that must complete first
        """
        return HttpXScan(scan_input=self.scan_input)
        # Requires HttpScan Task to be run prior
        return HttpXScan(scan_input=self.scan_input)

    def run(self):

        scheduled_scan_obj = self.scan_input
        scope_obj = scheduled_scan_obj.scan_data
        tool_instance_id = scheduled_scan_obj.current_tool_instance_id
        tool_obj = scheduled_scan_obj.current_tool
        tool_id = tool_obj.id

        http_output_file = self.input().path
        with open(http_output_file, 'r') as file_fd:
            data = file_fd.read()

        if len(data) == 0:
            logging.getLogger(__name__).error(
                "Httpx scan output file is empty")
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
                host_key = '%s:%s' % (target_str, port_str)

                # See if we have an host/port mapping already for this ip and port
                if host_key in scheduled_scan_obj.scan_data.host_port_obj_map:
                    host_port_dict = scheduled_scan_obj.scan_data.host_port_obj_map[host_key]
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
                    host_obj = data_model.Host()
                    host_obj.collection_tool_instance_id = tool_instance_id

                    ip_object = netaddr.IPAddress(ip_str)
                    if ip_object.version == 4:
                        host_obj.ipv4_addr = str(ip_object)
                    elif ip_object.version == 6:
                        host_obj.ipv6_addr = str(ip_object)

                    host_id = host_obj.id

                    # Add host
                    ret_arr.append(host_obj)

                # If cname
                if 'cname' in httpx_scan:
                    cname = httpx_scan['cname']
                    if type(cname) == list:
                        for cname_inst in cname:
                            domain_obj = data_model.Domain(
                                parent_id=host_id)
                            domain_obj.collection_tool_instance_id = tool_instance_id
                            domain_obj.name = cname_inst
                            ret_arr.append(domain_obj)

                # Create Port object
                port_obj = data_model.Port(
                    parent_id=host_id)
                port_obj.collection_tool_instance_id = tool_instance_id
                port_obj.proto = 0
                port_obj.port = port_str

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
                        path_obj.collection_tool_instance_id = tool_instance_id
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
                        screenshot_obj.collection_tool_instance_id = tool_instance_id
                        screenshot_obj.screenshot = screenshot_bytes_b64
                        screenshot_obj.image_hash = image_hash_str

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
                    cert_obj.collection_tool_instance_id = tool_instance_id

                    if 'subject_an' in tls_data:
                        dns_names = tls_data['subject_an']
                        for dns_name in dns_names:
                            domain_obj = cert_obj.add_domain(
                                host_id, dns_name, tool_instance_id)
                            if domain_obj:
                                ret_arr.append(domain_obj)

                    if 'host' in tls_data:
                        common_name = tls_data['host']
                        if type(common_name) == list:
                            for common_name_inst in common_name:
                                domain_obj = cert_obj.add_domain(host_id,
                                                                 common_name_inst, tool_instance_id)
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
                                domain_obj = cert_obj.add_domain(host_id,
                                                                 common_name_inst, tool_instance_id)
                                if domain_obj:
                                    ret_arr.append(domain_obj)

                        else:
                            domain_obj = cert_obj.add_domain(
                                host_id, common_name, tool_instance_id)
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
                    # logging.getLogger(__name__).debug("Found domain in cert: %s" % domain_used)
                    endpoint_domain_id = cert_obj.domain_name_id_map[domain_used]

                # Add http component
                component_obj = data_model.WebComponent(
                    parent_id=port_obj.id)
                component_obj.collection_tool_instance_id = tool_instance_id
                component_obj.name = 'http'
                ret_arr.append(component_obj)

                if 'tech' in httpx_scan:
                    tech_list = httpx_scan['tech']
                    for tech_entry in tech_list:

                        component_obj = data_model.WebComponent(
                            parent_id=port_obj.id)
                        component_obj.collection_tool_instance_id = tool_instance_id

                        if ":" in tech_entry:
                            tech_entry_arr = tech_entry.split(":")
                            component_obj.name = tech_entry_arr[0]
                            component_obj.version = tech_entry_arr[1]
                        else:
                            component_obj.name = tech_entry

                        ret_arr.append(component_obj)

                # Add collection module
                if 'raw_header' in httpx_scan:
                    output = httpx_scan['raw_header']
                    if output and len(output) > 0:
                        module_obj = data_model.CollectionModule(
                            parent_id=tool_id)
                        module_obj.collection_tool_instance_id = tool_instance_id
                        module_obj.name = 'http-response-headers'

                        ret_arr.append(module_obj)
                        temp_module_id = module_obj.id

                        # Add module output
                        module_output_obj = data_model.CollectionModuleOutput(
                            parent_id=temp_module_id)
                        module_output_obj.collection_tool_instance_id = tool_instance_id
                        module_output_obj.output = output
                        module_output_obj.port_id = port_obj.id

                        ret_arr.append(module_output_obj)

                # Add http body
                if 'body' in httpx_scan:
                    output = httpx_scan['body']
                    if output and len(output) > 0:
                        module_obj = data_model.CollectionModule(
                            parent_id=tool_id)
                        module_obj.collection_tool_instance_id = tool_instance_id
                        module_obj.name = 'http-response-body'

                        ret_arr.append(module_obj)
                        temp_module_id = module_obj.id

                        # Add module output
                        module_output_obj = data_model.CollectionModuleOutput(
                            parent_id=temp_module_id)
                        module_output_obj.collection_tool_instance_id = tool_instance_id
                        module_output_obj.output = output
                        module_output_obj.port_id = port_obj.id

                        ret_arr.append(module_output_obj)

                # Add http endpoint
                http_endpoint_obj = data_model.HttpEndpoint(
                    parent_id=port_obj.id)
                http_endpoint_obj.collection_tool_instance_id = tool_instance_id
                http_endpoint_obj.web_path_id = web_path_id

                # Add the endpoint
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

                # Add the endpoint data
                ret_arr.append(http_endpoint_data_obj)

        # Import, Update, & Save
        self.import_results(scheduled_scan_obj, ret_arr)
