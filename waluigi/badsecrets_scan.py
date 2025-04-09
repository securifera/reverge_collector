import json
import os
import luigi
import multiprocessing
import traceback
import requests
import time
import socket

from luigi.util import inherits
from tqdm import tqdm
from multiprocessing.pool import ThreadPool
from waluigi import scan_utils
from waluigi import data_model
from badsecrets.base import carve_all_modules


proxies = None


class Badsecrets(data_model.WaluigiTool):

    def __init__(self):
        self.name = 'badsecrets'
        self.collector_type = data_model.CollectorType.ACTIVE.value
        self.scan_order = 10
        self.args = ""
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


def request_wrapper(url_obj):

    url = url_obj['url']
    output = ''

    print("[*} URL: %s" % url)
    multiprocessing.log_to_stderr()
    headers = {
        'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"}
    count = 0
    while True:
        try:
            resp = requests.get(url, headers=headers,
                                verify=False, proxies=proxies, timeout=3)

            # Check if there are any issues
            if resp.status_code == 200:
                output = carve_all_modules(requests_response=resp)

            break
        except Exception as e:
            count += 1
            time.sleep(1)
            if count > 2:
                break

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

        target_map = scheduled_scan_obj.scan_data.host_port_obj_map
        for target_key in target_map:

            target_obj_dict = target_map[target_key]
            port_obj = target_obj_dict['port_obj']
            port_id = port_obj.id
            port_str = port_obj.port
            secure = port_obj.secure

            host_obj = target_obj_dict['host_obj']
            ip_addr = host_obj.ipv4_addr

            # Get endpoint map
            http_endpoint_list = []
            http_endpoint_port_id_map = scheduled_scan_obj.scan_data.http_endpoint_port_id_map
            if port_id in http_endpoint_port_id_map:
                http_endpoint_list = http_endpoint_port_id_map[port_id]

            if len(http_endpoint_list) == 0:
                print("[*] Endpoint list is empty")

            target_arr = target_key.split(":")
            if target_arr[0] != ip_addr:
                domain_str = target_arr[0]

                # Get the IP of the TLD
                try:
                    socket.gethostbyname(domain_str).strip()
                except Exception:
                    print("[-] Exception resolving domain: %s" %
                          domain_str)
                    continue

                # Add for domain
                url_str = scan_utils.construct_url(
                    domain_str, port_str, secure)

                for endpoint_obj in http_endpoint_list:
                    http_endpoint_id = endpoint_obj.id
                    path_id = endpoint_obj.web_path_id
                    if path_id in scheduled_scan_obj.scan_data.path_map:
                        path_obj = scheduled_scan_obj.scan_data.path_map[path_id]
                        web_path = path_obj.web_path
                        endpoint_url = url_str + web_path

                        # Add the URL
                        url_list.append(
                            {'port_id': port_id, 'http_endpoint_id': http_endpoint_id, 'url': endpoint_url})
                    else:
                        print("[*] No path obj for endpoint")

            # ADD FOR IP
            url_str = scan_utils.construct_url(ip_addr, port_str, secure)

            for endpoint_obj in http_endpoint_list:
                http_endpoint_id = endpoint_obj.id
                path_id = endpoint_obj.web_path_id
                if path_id in scheduled_scan_obj.scan_data.path_map:
                    path_obj = scheduled_scan_obj.scan_data.path_map[path_id]
                    web_path = path_obj.web_path
                    endpoint_url = url_str + web_path

                    # Add the URL
                    url_list.append(
                        {'port_id': port_id, 'http_endpoint_id': http_endpoint_id, 'url': endpoint_url})
                else:
                    print("[*] No path obj for endpoint")

            # Run threaded
            pool = ThreadPool(processes=10)
            thread_list = []

            # Add the url
            print(url_list)
            for url_obj in url_list:
                thread_list.append(pool.apply_async(
                    request_wrapper, (url_obj,)))

            # Close the pool
            pool.close()

            # Loop through thread function calls and update progress
            for thread_obj in tqdm(thread_list):
                ret_obj = thread_obj.get()
                if ret_obj:
                    output_file_list.append(ret_obj)

        results_dict = {'output_list': output_file_list}

        # Write output file
        with open(output_file_path, 'w') as file_fd:
            file_fd.write(json.dumps(results_dict))


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
            print(scan_data_dict)

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
