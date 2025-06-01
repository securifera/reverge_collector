import binascii
import hashlib
import json
import os
import luigi
import multiprocessing
# import traceback
import requests
import time
import logging
import netaddr

from luigi.util import inherits
from waluigi import scan_utils
from waluigi import data_model
from badsecrets.base import carve_all_modules
from urllib.parse import urlparse

logger = logging.getLogger(__name__)
url_set = set()
path_hash_map = {}


class Badsecrets(data_model.WaluigiTool):

    def __init__(self):
        self.name = 'badsecrets'
        self.collector_type = data_model.CollectorType.ACTIVE.value
        self.scan_order = 10
        self.args = ""
        self.description = 'A pure python library for identifying the use of known or very weak cryptographic secrets across a variety of web application platforms.'
        self.project_url = "https://github.com/blacklanternsecurity/badsecrets"
        self.scan_func = Badsecrets.badsecrets_scan_func
        self.import_func = Badsecrets.badsecrets_import

    @staticmethod
    def badsecrets_scan_func(scan_input):
        luigi_run_result = luigi.build([BadSecretsScan(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True

    @staticmethod
    def badsecrets_import(scan_input):
        luigi_run_result = luigi.build([ImportBadSecretsOutput(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


def queue_scan(url_dict):

    global url_set

    url = url_dict['url']
    if url not in url_set:
        url_set.add(url)
        return scan_utils.executor.submit(request_wrapper, url_dict)


def request_wrapper(url_obj):

    url = url_obj['url']
    output = ''

    logger.debug("Scanning URL: %s" % url)
    multiprocessing.log_to_stderr()
    headers = {
        'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"}
    count = 0
    while True:
        try:
            resp = requests.get(url, headers=headers, verify=False, timeout=3)

            # Check if there are any issues
            if resp.status_code == 200:
                output = carve_all_modules(requests_response=resp, url=url)

            break
        except Exception as e:
            logger.error("Error scanning URL %s: %s" % (url, str(e)))
            count += 1
            time.sleep(1)
            if count > 2:
                break

    # if output:
    #    logger.debug("Output for URL %s: %s" % (url, output))

    url_obj['output'] = output
    return url_obj


class BadSecretsScan(luigi.Task):

    scan_input = luigi.Parameter()

    def output(self):

        scheduled_scan_obj = self.scan_input
        scan_id = scheduled_scan_obj.id

        # Init directory
        tool_name = scheduled_scan_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)

        # path to input file
        http_outputs_file = dir_path + os.path.sep + "badsecrets_outputs_" + scan_id
        return luigi.LocalTarget(http_outputs_file)

    def run(self):

        scheduled_scan_obj = self.scan_input

        # Get output file path
        output_file_path = self.output().path
        output_file_list = []
        url_list = []

        scope_obj = scheduled_scan_obj.scan_data
        url_list = scope_obj.get_scope_urls()

        futures = []
        target_map = scope_obj.host_port_obj_map
        if len(target_map) > 0:

            for target_key in target_map:

                ip_set = set()
                target_obj_dict = target_map[target_key]
                port_obj = target_obj_dict['port_obj']
                port_id = port_obj.id
                port_str = port_obj.port
                secure = port_obj.secure

                host_obj = target_obj_dict['host_obj']
                ip_addr = host_obj.ipv4_addr
                ip_set.add(ip_addr)

                # Get endpoint map
                http_endpoint_list = []
                http_endpoint_port_id_map = scheduled_scan_obj.scan_data.http_endpoint_port_id_map
                if port_id in http_endpoint_port_id_map:
                    http_endpoint_list = http_endpoint_port_id_map[port_id]

                # Add each of the domains for the host
                host_id = host_obj.id
                if host_id in scope_obj.domain_host_id_map:
                    temp_domain_list = scope_obj.domain_host_id_map[host_id]
                    for domain_obj in temp_domain_list:

                        domain_name = domain_obj.name
                        ip_set.add(domain_name)

                # Loop through the IP set and construct URLs
                for ip_addr in ip_set:

                    url_str = scan_utils.construct_url(
                        ip_addr, port_str, secure)

                    for endpoint_obj in http_endpoint_list:
                        http_endpoint_id = endpoint_obj.id
                        path_id = endpoint_obj.web_path_id
                        if path_id in scheduled_scan_obj.scan_data.path_map:
                            path_obj = scheduled_scan_obj.scan_data.path_map[path_id]
                            web_path = path_obj.web_path
                            endpoint_url = url_str + web_path

                            # Add the URL
                            url_obj = {
                                'port_id': port_id, 'http_endpoint_id': http_endpoint_id, 'url': endpoint_url}
                            future_inst = queue_scan(url_obj)
                            if future_inst:
                                futures.append(future_inst)

        elif len(url_list) > 0:

            for url in url_list:
                url_obj = {'port_id': None,
                           'http_endpoint_id': None, 'url': url}
                future_inst = queue_scan(url_obj)
                if future_inst:
                    futures.append(future_inst)

        else:
            logger.debug("No targets to scan for BadSecrets")

        # If there are any futures, wait for them to complete
        if len(futures) > 0:
            scan_proc_inst = data_model.ToolExecutor(futures)
            scheduled_scan_obj.register_tool_executor(
                scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

            # Wait for the tasks to complete and retrieve results
            for future in futures:
                ret_obj = future.result()
                if ret_obj:
                    output_file_list.append(ret_obj)

        results_dict = {'output_list': output_file_list}

        # Write output file
        with open(output_file_path, 'w') as file_fd:
            file_fd.write(json.dumps(results_dict))


def create_port_objs(ret_arr, url):
    """
    Create objects from the url and add to the return array
    """
    global path_hash_map

    if url:

        port_id = None
        u = urlparse(url)
        host = u.netloc
        scheme = u.scheme
        port = None
        domain_str = None
        if ":" in host:
            host_arr = host.split(":")
            domain_str = host_arr[0].lower()
            port = int(host_arr[1])
        else:
            domain_str = host
            port = None

        web_path = u.path or "/"

        # Fix up port
        if scheme == 'http':
            secure = 0
            if port is None:
                port = 80
        elif scheme == 'https':
            secure = 1
            if port is None:
                port = 443

        ip_object = netaddr.IPAddress(domain_str)

        # Create Host object
        host_obj = data_model.Host()
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
        port_obj.port = str(port)
        port_id = port_obj.id
        port_obj.secure = secure

        # Add port
        ret_arr.append(port_obj)

        hashobj = hashlib.sha1
        hashobj.update(web_path.encode())
        path_hash = hashobj.digest()
        hex_str = binascii.hexlify(path_hash).decode()
        web_path_hash = hex_str

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

        # Add http endpoint
        http_endpoint_obj = data_model.HttpEndpoint(
            parent_id=port_obj.id)
        http_endpoint_obj.web_path_id = web_path_id

        ret_arr.append(port_obj)

    return ret_arr


@inherits(BadSecretsScan)
class ImportBadSecretsOutput(data_model.ImportToolXOutput):

    def requires(self):
        # Requires BadSecretsScan Task to be run prior
        return BadSecretsScan(scan_input=self.scan_input)

    def run(self):

        http_output_file = self.input().path
        with open(http_output_file, 'r') as file_fd:
            data = file_fd.read()

        if len(data) > 0:

            ret_arr = []
            scan_data_dict = json.loads(data)

            # Get data and map
            output_list = scan_data_dict['output_list']
            if len(output_list) > 0:

                # Parse the output
                for entry in output_list:

                    output = entry['output']
                    http_endpoint_id = entry['http_endpoint_id']
                    port_id = entry['port_id']

                    if output and len(output) > 0:
                        for finding in output:
                            finding_type = finding['type']
                            if finding_type == 'SecretFound':

                                if 'secret' in finding:
                                    secret_val = finding['secret']

                                    if 'description' in finding:
                                        vuln_desc = finding['description']

                                        if 'Secret' in vuln_desc:
                                            vuln_name = vuln_desc['Secret']

                                            if port_id is None:
                                                ret_arr = create_port_objs(
                                                    ret_arr, entry['url'])

                                            # Add vuln
                                            vuln_obj = data_model.Vuln(
                                                parent_id=port_id)
                                            vuln_obj.name = vuln_name
                                            vuln_obj.vuln_details = secret_val
                                            vuln_obj.endpoint_id = http_endpoint_id
                                            ret_arr.append(vuln_obj)

            # Import, Update, & Save
            scheduled_scan_obj = self.scan_input
            self.import_results(scheduled_scan_obj, ret_arr)
