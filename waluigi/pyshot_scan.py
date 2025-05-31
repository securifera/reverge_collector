import json
import os
import binascii
import luigi
import traceback
import hashlib
import base64
import logging

from luigi.util import inherits
from pyshot import pyshot as pyshot_lib
from waluigi import scan_utils
from os.path import exists
from waluigi import data_model


logger = logging.getLogger(__name__)
url_set = set()


class Pyshot(data_model.WaluigiTool):

    def __init__(self):
        self.name = 'pyshot'
        self.description = 'A python library that can be used for taking screenshots of web pages using PhantomJS.'
        self.project_url = 'https://github.com/securifera/pyshot'
        self.collector_type = data_model.CollectorType.ACTIVE.value
        self.scan_order = 8
        self.args = ""
        self.scan_func = Pyshot.pyshot_scan_func
        self.import_func = Pyshot.pyshot_import

    @staticmethod
    def pyshot_scan_func(scan_input):
        luigi_run_result = luigi.build([PyshotScan(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True

    @staticmethod
    def pyshot_import(scan_input):
        luigi_run_result = luigi.build([ImportPyshotOutput(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


def pyshot_wrapper(ip_addr, port, dir_path, ssl_val, port_id, query_arg="", domain=None, http_endpoint_data_id=None):

    ret_msg = ""
    try:
        # domain_str = ''
        # if domain:
        #    domain_str = domain
        # logger.debug("[+] Running Pyshot scan on %s:%s%s (%s)" %
        #             (ip_addr, port, query_arg, domain_str))
        pyshot_lib.take_screenshot(host=ip_addr, port_arg=port, query_arg=query_arg,
                                   dest_dir=dir_path, secure=ssl_val, port_id=port_id, domain=domain, endpoint_id=http_endpoint_data_id)
    except Exception as e:
        # Here we add some debugging help. If multiprocessing's
        # debugging is on, it will arrange to log the traceback
        ret_msg += "[-] Pyshot scan thread exception."
        ret_msg += str(traceback.format_exc())
        # Re-raise the original exception so the Pool worker can
        # clean up

    return ret_msg


def queue_scan(host, port_str, dir_path, secure, port_id, query_arg="", domain_str=None, http_endpoint_data_id=None):

    global url_set

    target_str = host
    if domain_str:
        target_str = domain_str

    url = scan_utils.construct_url(target_str, port_str, secure, query_arg)
    if url not in url_set:
        url_set.add(url)
        return scan_utils.executor.submit(pyshot_wrapper, host, port_str,
                                          dir_path, secure, port_id, query_arg, domain_str, http_endpoint_data_id)


class PyshotScan(luigi.Task):

    scan_input = luigi.Parameter()

    def output(self):

        scheduled_scan_obj = self.scan_input
        scan_id = scheduled_scan_obj.id

        # Init directory
        tool_name = scheduled_scan_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)

        # Meta file when complete
        meta_file = '%s%s%s' % (dir_path, os.path.sep, 'screenshots.meta')

        return luigi.LocalTarget(meta_file)

    def run(self):

        global url_set
        # Ensure output folder exists
        dir_path = os.path.dirname(self.output().path)
        url_set = set()

        scheduled_scan_obj = self.scan_input

        scope_obj = scheduled_scan_obj.scan_data
        target_map = scope_obj.host_port_obj_map
        http_endpoint_port_id_map = scope_obj.http_endpoint_port_id_map
        web_path_map = scope_obj.path_map
        domain_map = scope_obj.domain_map
        endpoint_data_endpoint_id_map = scope_obj.endpoint_data_endpoint_id_map

        # logger.debug("[+] Running Pyshot scan on %s" %
        #             str(target_map))
        # logger.debug("[+] Running Pyshot scan on %s" %
        #             str(domain_map))

        futures = []
        for target_key in target_map:

            query_arg = ""
            target_obj_dict = target_map[target_key]
            port_obj = target_obj_dict['port_obj']

            port_id = port_obj.id
            port_str = port_obj.port
            secure = port_obj.secure

            host_obj = target_obj_dict['host_obj']
            host_id = host_obj.id
            ip_addr = host_obj.ipv4_addr

            # Add domain if it is different from the IP
            domain_str_orig = None
            target_arr = target_key.split(":")
            if target_arr[0] != ip_addr:
                domain_str_orig = target_arr[0]

            if port_id in http_endpoint_port_id_map:
                http_endpoint_obj_list = http_endpoint_port_id_map[port_id]
                for http_endpoint_obj in http_endpoint_obj_list:

                    query_arg = ""
                    domain_str = domain_str_orig
                    http_endpoint_data_id = None
                    host = ip_addr
                    web_path_id = http_endpoint_obj.web_path_id
                    if web_path_id and web_path_id in web_path_map:
                        web_path_obj = web_path_map[web_path_id]
                        query_arg = web_path_obj.web_path

                    if http_endpoint_obj.id in endpoint_data_endpoint_id_map:
                        http_endpoint_data_obj_list = endpoint_data_endpoint_id_map[
                            http_endpoint_obj.id]

                        for http_endpoint_data_obj in http_endpoint_data_obj_list:

                            domain_str = None
                            http_endpoint_data_id = http_endpoint_data_obj.id
                            domain_id = http_endpoint_data_obj.domain_id
                            if domain_id and domain_id in domain_map:
                                domain_obj = domain_map[domain_id]
                                domain_str = domain_obj.name
                                host = domain_str
                            elif host_id in scope_obj.domain_host_id_map:

                                # Take screenshots for any domains associated with the host
                                temp_domain_list = scope_obj.domain_host_id_map[host_id]
                                for domain_obj in temp_domain_list:
                                    domain_name = domain_obj.name
                                    future_inst = queue_scan(domain_name, port_str, dir_path,
                                                             secure, port_id, query_arg, domain_name)
                                    if future_inst:
                                        futures.append(future_inst)

                            future_inst = queue_scan(host, port_str, dir_path,
                                                     secure, port_id, query_arg, domain_str, http_endpoint_data_id)
                            if future_inst:
                                futures.append(future_inst)

                    future_inst = queue_scan(host, port_str, dir_path,
                                             secure, port_id, query_arg, domain_str)
                    if future_inst:
                        futures.append(future_inst)
            else:

                # Add for IP address
                future_inst = queue_scan(ip_addr, port_str, dir_path,
                                         secure, port_id, query_arg, domain_str_orig)
                if future_inst:
                    futures.append(future_inst)

                # Add for domains in the scope
                if host_id in scope_obj.domain_host_id_map:
                    temp_domain_list = scope_obj.domain_host_id_map[host_id]
                    for domain_obj in temp_domain_list:

                        domain_name = domain_obj.name
                        future_inst = queue_scan(domain_name, port_str, dir_path,
                                                 secure, port_id, query_arg, domain_name)
                        if future_inst:
                            futures.append(future_inst)

        scan_proc_inst = data_model.ToolExecutor(futures)
        scheduled_scan_obj.register_tool_executor(
            scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

        # Wait for the tasks to complete and retrieve results
        for future in futures:
            future.result()


@inherits(PyshotScan)
class ImportPyshotOutput(data_model.ImportToolXOutput):

    def requires(self):
        # Requires PyshotScan Task to be run prior
        return PyshotScan(scan_input=self.scan_input)

    def run(self):

        meta_file = self.input().path
        scheduled_scan_obj = self.scan_input
        scan_id = scheduled_scan_obj.scan_id
        recon_manager = scheduled_scan_obj.scan_thread.recon_manager
        tool_obj = scheduled_scan_obj.current_tool
        tool_id = tool_obj.id

        path_hash_map = {}
        screenshot_hash_map = {}
        domain_name_id_map = {}

        if os.path.exists(meta_file):

            with open(meta_file, 'r') as file_fd:
                lines = file_fd.readlines()

            count = 0
            import_data_arr = []
            for line in lines:
                ret_arr = []

                screenshot_meta = json.loads(line)
                filename = screenshot_meta['file_path']
                if filename and exists(filename):
                    url = screenshot_meta['url']
                    web_path = screenshot_meta['path']
                    port_id = screenshot_meta['port_id']
                    status_code = screenshot_meta['status_code']
                    http_endpoint_data_id = screenshot_meta['endpoint_id']

                    # Hash the image
                    screenshot_id = None
                    image_data = b""
                    hash_alg = hashlib.sha1
                    with open(filename, "rb") as rf:
                        image_data = rf.read()
                        hashobj = hash_alg()
                        hashobj.update(image_data)
                        image_hash = hashobj.digest()
                        image_hash_str = binascii.hexlify(image_hash).decode()
                        screenshot_bytes_b64 = base64.b64encode(
                            image_data).decode()

                        if image_hash_str in screenshot_hash_map:
                            screenshot_obj = screenshot_hash_map[image_hash_str]
                        else:
                            screenshot_obj = data_model.Screenshot()
                            screenshot_obj.screenshot = screenshot_bytes_b64
                            screenshot_obj.image_hash = image_hash_str

                            # Add to map and the object list
                            screenshot_hash_map[image_hash_str] = screenshot_obj

                        ret_arr.append(screenshot_obj)

                        screenshot_id = screenshot_obj.id

                    hashobj = hash_alg()
                    hashobj.update(web_path.encode())
                    path_hash = hashobj.digest()
                    hex_str = binascii.hexlify(path_hash).decode()
                    web_path_hash = hex_str

                    # Domain key exists and is not None
                    endpoint_domain_id = None
                    if 'domain' in screenshot_meta and screenshot_meta['domain']:
                        domain_str = screenshot_meta['domain']
                        if domain_str in domain_name_id_map:
                            domain_obj = domain_name_id_map[domain_str]
                        else:
                            domain_obj = data_model.Domain()
                            domain_obj.name = domain_str
                            domain_name_id_map[domain_str] = domain_obj

                        # Add domain
                        ret_arr.append(domain_obj)
                        # Set endpoint id
                        endpoint_domain_id = domain_obj.id

                    if web_path_hash in path_hash_map:
                        path_obj = path_hash_map[web_path_hash]
                    else:
                        path_obj = data_model.ListItem()
                        path_obj.web_path = web_path
                        path_obj.web_path_hash = web_path_hash

                        # Add to map and the object list
                        path_hash_map[web_path_hash] = path_obj

                    # Add path object
                    ret_arr.append(path_obj)

                    web_path_id = path_obj.id

                    # Add http endpoint
                    http_endpoint_obj = data_model.HttpEndpoint(
                        parent_id=port_id)
                    http_endpoint_obj.web_path_id = web_path_id

                    # Add the endpoint
                    ret_arr.append(http_endpoint_obj)

                    # Add http endpoint data
                    http_endpoint_data_obj = data_model.HttpEndpointData(
                        parent_id=http_endpoint_obj.id)
                    http_endpoint_data_obj.domain_id = endpoint_domain_id
                    http_endpoint_data_obj.status = status_code
                    http_endpoint_data_obj.screenshot_id = screenshot_id

                    # Set the object id if the object already exists
                    if http_endpoint_data_id:
                        http_endpoint_data_obj.id = http_endpoint_data_id

                    # Add the endpoint
                    ret_arr.append(http_endpoint_data_obj)

                    if len(ret_arr) > 0:

                        record_map = {}
                        import_arr = []
                        for obj in ret_arr:
                            record_map[obj.id] = obj
                            flat_obj = obj.to_jsonable()
                            import_arr.append(flat_obj)

                        # Import the ports to the manager
                        updated_record_map = recon_manager.import_data(
                            scan_id, tool_id, import_arr)

                        # Update the records
                        updated_import_arr = data_model.update_scope_array(
                            record_map, updated_record_map)

                        import_data_arr.extend(updated_import_arr)

                        # Update the scan scope
                        scheduled_scan_obj.scan_data.update(record_map)

                    count += 1

            # Write imported data to file
            tool_import_file = self.output().path
            with open(tool_import_file, 'w') as import_fd:
                import_fd.write(json.dumps(import_data_arr))

            logger.debug("Imported %d screenshots to manager." % (count))

        else:

            logger.error("[-] Pyshot meta file does not exist.")
