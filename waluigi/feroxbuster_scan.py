from functools import partial
import json
import os
import netaddr
import socket
import luigi
import traceback
import socket
import random
import hashlib
import binascii
import logging

from luigi.util import inherits
from waluigi import scan_utils
from urllib.parse import urlparse
from waluigi import data_model

logger = logging.getLogger(__name__)
url_set = set()


class Feroxbuster(data_model.WaluigiTool):

    def __init__(self):
        self.name = 'feroxbuster'
        self.description = 'Feroxbuster is a fast, simple, and flexible web directory scanner written in Rust'
        self.project_url = "https://github.com/epi052/feroxbuster"
        self.collector_type = data_model.CollectorType.ACTIVE.value
        self.scan_order = 10
        self.args = "--rate-limit 50 -s 200 -n"
        self.scan_func = Feroxbuster.feroxbuster_scan_func
        self.import_func = Feroxbuster.feroxbuster_import

    @staticmethod
    def feroxbuster_scan_func(scan_input):
        luigi_run_result = luigi.build([FeroxScan(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True

    @staticmethod
    def feroxbuster_import(scan_input):
        luigi_run_result = luigi.build([ImportFeroxOutput(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


def queue_url(url_to_id_map, domain_str, port_str, secure, output_dir, host_id, port_id):

    global url_set
    url_str = scan_utils.construct_url(domain_str, port_str, secure)

    if url_str not in url_set:
        url_set.add(url_str)
        rand_str = str(random.randint(1000000, 2000000))

        # Add to port id map
        scan_output_file_path = output_dir + os.path.sep + "ferox_out_" + rand_str
        url_to_id_map[url_str] = {
            'port_id': port_id, 'host_id': host_id, 'output_file': scan_output_file_path}


class FeroxScan(luigi.Task):

    scan_input = luigi.Parameter()

    def output(self):

        scheduled_scan_obj = self.scan_input
        scan_id = scheduled_scan_obj.id

        # Init directory
        tool_name = scheduled_scan_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)

        scan_outputs_file = dir_path + os.path.sep + "ferox_outputs_" + scan_id
        return luigi.LocalTarget(scan_outputs_file)

    def run(self):

        global url_set
        url_set = set()

        scheduled_scan_obj = self.scan_input

        # Get output file path
        output_file_path = self.output().path
        output_dir = os.path.dirname(output_file_path)

        url_to_id_map = {}
        tool_args = scheduled_scan_obj.current_tool.args
        if tool_args:
            tool_args = tool_args.split(" ")

        scan_wordlist = None
        if scheduled_scan_obj.current_tool.wordlist_path and os.path.exists(scheduled_scan_obj.current_tool.wordlist_path):
            scan_wordlist = scheduled_scan_obj.current_tool.wordlist_path

        target_map = scheduled_scan_obj.scan_data.host_port_obj_map
        domain_host_id_map = scheduled_scan_obj.scan_data.domain_host_id_map

        for target_key in target_map:

            target_obj_dict = target_map[target_key]
            port_obj = target_obj_dict['port_obj']
            port_id = port_obj.id
            port_str = port_obj.port
            secure = port_obj.secure

            host_obj = target_obj_dict['host_obj']
            ip_addr = host_obj.ipv4_addr
            host_id = host_obj.id

            # NEED TO REWORK THIS TO DETERMINE THIS BEST DOMAIN TO USE. SENDING FOR ALL DOMAINS IS EXCESSIVE
            # ADD FOR IP
            target_arr = target_key.split(":")
            if target_arr[0] != ip_addr:
                domain_str = target_arr[0]

                # Get the IP of the TLD
                try:
                    socket.gethostbyname(domain_str).strip()
                    ip_addr = domain_str
                except Exception:
                    print("[-] Exception resolving domain: %s" % domain_str)
                    continue

                queue_url(url_to_id_map, ip_addr, port_str,
                          secure, output_dir, host_id, port_id)

            else:
                # Add for IP
                queue_url(url_to_id_map, ip_addr, port_str,
                          secure, output_dir, host_id, port_id)

                # Add for each domain
                if host_id in domain_host_id_map:
                    domain_list = domain_host_id_map[host_id]
                    for domain_obj in domain_list:
                        domain_str = domain_obj.name
                        queue_url(url_to_id_map, domain_str, port_str,
                                  secure, output_dir, host_id, port_id)

        futures = []
        for target_url in url_to_id_map:

            # Get output file
            scan_output_file_path = url_to_id_map[target_url]['output_file']

            command = []
            if os.name != 'nt':
                command.append("sudo")

            command_arr = [
                "feroxbuster",
                "--json",
                "-k",  # Disable cert validation
                # "-q", # Quiet
                "-A",  # Random User Agent
                # "--thorough", # Collects words, extensions, and links in content
                # "--auto-tune", # Resets speed based on errors
                "--auto-bail",  # Quits after too many errors
                "-u",
                target_url,
                "-o",
                scan_output_file_path
            ]

            command.extend(command_arr)

            # Add optional arguments
            if tool_args and len(tool_args) > 0:
                command.extend(tool_args)

            # Add wordlist if provided
            if scan_wordlist:
                command.extend(['-w', scan_wordlist])

            callback_with_tool_id = partial(
                scheduled_scan_obj.register_tool_executor, scheduled_scan_obj.current_tool_instance_id)

            futures.append(scan_utils.executor.submit(
                scan_utils.process_wrapper, cmd_args=command, pid_callback=callback_with_tool_id))

        # Register futures
        scan_proc_inst = data_model.ToolExecutor(futures)
        scheduled_scan_obj.register_tool_executor(
            scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

        # Wait for the tasks to complete and retrieve results
        for future in futures:
            future.result()

        results_dict = {'url_to_id_map': url_to_id_map}

        # Write output file
        with open(output_file_path, 'w') as file_fd:
            file_fd.write(json.dumps(results_dict))


@inherits(FeroxScan)
class ImportFeroxOutput(data_model.ImportToolXOutput):

    def requires(self):
        # Requires HttpScan Task to be run prior
        return FeroxScan(scan_input=self.scan_input)

    def run(self):

        path_hash_map = {}
        domain_name_id_map = {}

        http_output_file = self.input().path
        with open(http_output_file, 'r') as file_fd:
            data = file_fd.read()

        ret_arr = []
        hash_alg = hashlib.sha1
        if len(data) > 0:
            scan_data_dict = json.loads(data)

            # Get data and map
            url_to_id_map = scan_data_dict['url_to_id_map']
            for url_str in url_to_id_map:

                obj_data = url_to_id_map[url_str]
                output_file = obj_data['output_file']
                port_id = obj_data['port_id']

                obj_arr = scan_utils.parse_json_blob_file(output_file)
                for web_result in obj_arr:

                    if 'type' in web_result:
                        result_type = web_result['type']

                        # Get the port object that maps to this url
                        if result_type == "response":

                            if 'status' in web_result:
                                status_code = web_result['status']
                                endpoint_url = None

                                if 'url' in web_result:
                                    endpoint_url = web_result['url']

                                    u = urlparse(endpoint_url)
                                    web_path_str = u.path
                                    if web_path_str and len(web_path_str) > 0:
                                        hashobj = hash_alg()
                                        hashobj.update(web_path_str.encode())
                                        path_hash = hashobj.digest()
                                        web_path_hash = binascii.hexlify(
                                            path_hash).decode()

                                    host = u.netloc
                                    if ":" in host:
                                        host_arr = host.split(":")
                                        domain_str = host_arr[0].lower
                                    else:
                                        domain_str = host

                                    # Check if the domain is an IP adress
                                    endpoint_domain_id = None
                                    try:
                                        netaddr.IPAddress(domain_str)
                                    except Exception as e:

                                        if domain_str in domain_name_id_map:
                                            endpoint_domain_id = domain_name_id_map[domain_str]
                                        else:
                                            domain_obj = data_model.Domain()
                                            domain_obj.name = domain_str

                                            # Add domain
                                            ret_arr.append(domain_obj)
                                            # Set endpoint id
                                            endpoint_domain_id = domain_obj.id
                                            domain_name_id_map[domain_str] = endpoint_domain_id

                                            # Add domain
                                            ret_arr.append(domain_obj)

                                    if web_path_hash in path_hash_map:
                                        path_obj = path_hash_map[web_path_hash]
                                    else:
                                        path_obj = data_model.ListItem()
                                        path_obj.web_path = web_path_str
                                        path_obj.web_path_hash = web_path_hash

                                        # Add to map and the object list
                                        path_hash_map[web_path_hash] = path_obj
                                        ret_arr.append(path_obj)

                                    web_path_id = path_obj.id

                                    # Create http endpoint
                                    http_endpoint_obj = data_model.HttpEndpoint(
                                        parent_id=port_id)
                                    http_endpoint_obj.web_path_id = web_path_id

                                    # Add the endpoint
                                    ret_arr.append(http_endpoint_obj)

                                    http_endpoint_data_obj = data_model.HttpEndpointData(
                                        parent_id=http_endpoint_obj.id)
                                    http_endpoint_data_obj.domain_id = endpoint_domain_id
                                    http_endpoint_data_obj.status = status_code

                                    # Add the endpoint
                                    ret_arr.append(http_endpoint_data_obj)

        scheduled_scan_obj = self.scan_input
        self.import_results(scheduled_scan_obj, ret_arr)
