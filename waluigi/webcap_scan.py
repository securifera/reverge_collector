import json
import os
import binascii
import luigi
import traceback
import hashlib
import base64
import logging
import asyncio

from luigi.util import inherits
from webcap import Browser
from waluigi import scan_utils
from waluigi import data_model


future_map = {}


class Webcap(data_model.WaluigiTool):

    def __init__(self):
        self.name = 'pyshot'
        self.description = 'A python library that can be used for taking screenshots of web pages using Chrome and Webcap.'
        self.project_url = 'https://github.com/blacklanternsecurity/webcap'
        self.collector_type = data_model.CollectorType.ACTIVE.value
        self.scan_order = 8
        self.args = ""
        self.scan_func = Webcap.webcap_scan_func
        self.import_func = Webcap.webcap_import

    @staticmethod
    def webcap_scan_func(scan_input):
        luigi_run_result = luigi.build([WebcapScan(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True

    @staticmethod
    def webcap_import(scan_input):
        luigi_run_result = luigi.build([ImportWebcapOutput(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


async def webcap_asyncio(future_map):

    ret_list = []
    # create a browser instance
    browser = Browser()
    # start the browser
    await browser.start()

    for url, scan_tuple in future_map.items():
        port_id, http_endpoint_data_id, domain_str, path = scan_tuple
        url_entry = {'port_id': port_id,
                     'http_endpoint_data_id': http_endpoint_data_id, 'path': path, 'domain': domain_str}

        # take a screenshot
        webscreenshot = await browser.screenshot(url)
        url_entry['url'] = url
        url_entry['image_data'] = base64.b64encode(webscreenshot.blob).decode()
        url_entry['status_code'] = webscreenshot.status_code
        url_entry['title'] = webscreenshot.title
        ret_list.append(url_entry)

    # stop the browser
    await browser.stop()

    return ret_list


def webcap_wrapper(future_map):

    return asyncio.run(webcap_asyncio(future_map))


def queue_scan(host, port_str, secure, port_id, query_arg="", domain_str=None, http_endpoint_data_id=None):

    global future_map

    target_str = host
    if domain_str:
        target_str = domain_str

    url = scan_utils.construct_url(target_str, port_str, secure, query_arg)
    if url in future_map:
        scan_tuple = future_map[url]
        port_id, prev_http_endpoint_data_id, domain_str, path = scan_tuple
        # the previous http endoint is None then switch it out to avoid duplicates
        if http_endpoint_data_id is not None and prev_http_endpoint_data_id is None:
            scan_tuple = (port_id, http_endpoint_data_id,
                          domain_str, query_arg)
            future_map[url] = scan_tuple
            return

    else:
        scan_tuple = (port_id, http_endpoint_data_id, domain_str, query_arg)
        future_map[url] = scan_tuple

    return


class WebcapScan(luigi.Task):

    scan_input = luigi.Parameter()

    def output(self):

        scheduled_scan_obj = self.scan_input
        scan_id = scheduled_scan_obj.id

        # Init directory
        tool_name = scheduled_scan_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)

        # Meta file when complete
        meta_file = '%s%s%s' % (dir_path, os.path.sep, 'screenshots.json')

        return luigi.LocalTarget(meta_file)

    def run(self):

        global future_map
        # Ensure output folder exists
        dir_path = os.path.dirname(self.output().path)

        scheduled_scan_obj = self.scan_input

        scope_obj = scheduled_scan_obj.scan_data
        target_map = scope_obj.host_port_obj_map
        http_endpoint_port_id_map = scope_obj.http_endpoint_port_id_map
        web_path_map = scope_obj.path_map
        domain_map = scope_obj.domain_map
        endpoint_data_endpoint_id_map = scope_obj.endpoint_data_endpoint_id_map

        future_map = {}
        for target_key in target_map:

            query_arg = "/"
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

                    query_arg = "/"
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
                                    queue_scan(domain_name, port_str, secure, port_id,
                                               query_arg, domain_name, http_endpoint_data_id)

                            queue_scan(host, port_str, secure, port_id,
                                       query_arg, domain_str, http_endpoint_data_id)

                    else:
                        queue_scan(
                            host, port_str, secure, port_id, query_arg, domain_str)

            else:

                # Add for IP address
                queue_scan(ip_addr, port_str, secure, port_id,
                           query_arg, domain_str_orig)

                # Add for domains in the scope
                if host_id in scope_obj.domain_host_id_map:
                    temp_domain_list = scope_obj.domain_host_id_map[host_id]
                    for domain_obj in temp_domain_list:

                        domain_name = domain_obj.name
                        queue_scan(domain_name, port_str, secure,
                                   port_id, query_arg, domain_name)

        # Submit the tuples
        futures = []

        # Submit the scan task
        future_inst = scan_utils.executor.submit(
            webcap_wrapper, future_map)
        futures.append(future_inst)

        scan_proc_inst = data_model.ToolExecutor(futures)
        scheduled_scan_obj.register_tool_executor(
            scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

        # Wait for the tasks to complete and retrieve results
        ret_list = []
        for future in futures:
            ret_list.extend(future.result())

        # Write the results to the output file
        meta_file = '%s%s%s' % (dir_path, os.path.sep, 'screenshots.json')
        with open(meta_file, 'w') as f:
            f.write(json.dumps(ret_list))

        logging.getLogger(__name__).debug(
            "WebcapScan completed. %d screenshots captured." % len(ret_list))


@inherits(WebcapScan)
class ImportWebcapOutput(data_model.ImportToolXOutput):

    def requires(self):
        # Requires WebcapScan Task to be run prior
        return WebcapScan(scan_input=self.scan_input)

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
                data = file_fd.read()

            count = 0
            import_data_arr = []
            screenshot_array = json.loads(data)
            for screenshot_meta in screenshot_array:
                ret_arr = []

                web_path = screenshot_meta['path']
                port_id = screenshot_meta['port_id']
                status_code = screenshot_meta['status_code']
                screenshot_bytes_b64 = screenshot_meta['image_data']
                title = screenshot_meta['title']
                http_endpoint_data_id = screenshot_meta['http_endpoint_data_id']

                # Hash the image
                screenshot_id = None
                hash_alg = hashlib.sha1
                hashobj = hash_alg()
                hashobj.update(base64.b64decode(screenshot_bytes_b64))
                image_hash = hashobj.digest()
                image_hash_str = binascii.hexlify(image_hash).decode()

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
                http_endpoint_data_obj.title = title
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

            logging.getLogger(__name__).debug(
                "Imported %d screenshots to manager." % (count))

        else:

            logging.getLogger(__name__).error(
                "[-] Screenshot file does not exist.")
