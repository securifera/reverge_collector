import requests
import luigi
import os
import json
import time
import logging

from luigi.util import inherits
from waluigi import scan_utils
from waluigi import data_model

proxies = None
logger = logging.getLogger(__name__)


class Sectrails(data_model.WaluigiTool):

    def __init__(self):
        self.name = 'sectrails'
        self.collector_type = data_model.CollectorType.PASSIVE.value
        self.scan_order = 5
        self.args = ""
        self.import_func = Sectrails.import_sectrailsiplookup

    @staticmethod
    def import_sectrailsiplookup(scan_input):
        luigi_run_result = luigi.build([ImportSecTrailsIPLookupOutput(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


def request_wrapper(ip_addr, api_key):

    domain_set = set()
    ret_str = {'ip_addr': ip_addr}
    headers = {'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
               'Content-Type': "application/json",
               "apikey": api_key}
    ip_dict = {"ipv4": ip_addr}

    while True:
        r = requests.post('https://api.securitytrails.com/v1/search/list',
                          headers=headers, json={"filter": ip_dict}, verify=False, proxies=proxies)
        if r.status_code == 429:
            time.sleep(1)
            continue
        elif r.status_code != 200:
            logger.debug("Status code: %d" % r.status_code)
            logger.debug(r.text)
            raise RuntimeError("[-] Error getting securitytrails output.")
        break

    # Parse output
    content = r.json()
    if 'records' in content:
        record_arr = content['records']
        for record in record_arr:
            if 'hostname' in record:
                hostname = record['hostname']
                domain_set.add(hostname)

    ret_str['domains'] = list(domain_set)
    return ret_str


class SecTrailsIPLookupScan(luigi.Task):

    scan_input = luigi.Parameter()

    def output(self):

        scheduled_scan_obj = self.scan_input
        scan_id = scheduled_scan_obj.id

        # Init directory
        tool_name = scheduled_scan_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)

        # path to input file
        http_outputs_file = dir_path + os.path.sep + \
            "sectrails-ip-lookup-outputs-" + scan_id
        return luigi.LocalTarget(http_outputs_file)

    def run(self):

        scheduled_scan_obj = self.scan_input

        # Get output file path
        output_file_path = self.output().path

        ip_to_host_dict_map = {}
        api_key = scheduled_scan_obj.current_tool.api_key
        if api_key and len(api_key) > 0:

            target_map = scheduled_scan_obj.scan_data.host_port_obj_map
            if len(target_map) == 0:
                logger.debug("No target map in scan input")

            for target_key in target_map:

                target_obj_dict = target_map[target_key]
                host_obj = target_obj_dict['host_obj']
                ip_addr = host_obj.ipv4_addr

                # Add to port id map
                ip_to_host_dict_map[ip_addr] = {'host_id': host_obj.id}

                futures = []
                for ip_addr in ip_to_host_dict_map:
                    futures.append(scan_utils.executor.submit(
                        request_wrapper, ip_addr=ip_addr, api_key=api_key))

                # Register futures
                scan_proc_inst = data_model.ToolExecutor(futures)
                scheduled_scan_obj.register_tool_executor(
                    scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

                # Loop through thread function calls and update progress
                for future in futures:
                    ret_dict = future.result()
                    # Get IP from results
                    ip_addr = ret_dict['ip_addr']
                    # Get host dict from map
                    host_dict = ip_to_host_dict_map[ip_addr]
                    # Add any domains
                    host_dict['domains'] = ret_dict['domains']
            else:
                logger.error("No target map in scan input")
        else:
            logger.error("No api key in scan input")

        results_dict = {'ip_to_host_dict_map': ip_to_host_dict_map}

        # Write output file
        with open(output_file_path, 'w') as file_fd:
            file_fd.write(json.dumps(results_dict))


@inherits(SecTrailsIPLookupScan)
class ImportSecTrailsIPLookupOutput(data_model.ImportToolXOutput):

    def requires(self):
        return SecTrailsIPLookupScan(scan_input=self.scan_input)

    def run(self):

        scan_output_file = self.input().path
        with open(scan_output_file, 'r') as file_fd:
            data = file_fd.read()

        obj_map = {}
        if len(data) > 0:
            scan_data_dict = json.loads(data)

            # Get data and map
            ip_to_host_dict_map = scan_data_dict['ip_to_host_dict_map']
            for ip_addr in ip_to_host_dict_map:
                host_dict = ip_to_host_dict_map[ip_addr]
                host_id = host_dict['host_id']
                domains = host_dict['domains']

                for domain in domains:
                    domain_obj = data_model.Domain(parent_id=host_id)
                    domain_obj.name = domain

                    # Add domain
                    obj_map[domain_obj.id] = domain_obj

            ret_arr = list(obj_map.values())

            if len(ret_arr) > 0:
                # Import, Update, & Save
                scheduled_scan_obj = self.scan_input
                self.import_results(scheduled_scan_obj, ret_arr)
