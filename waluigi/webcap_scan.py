import json
import os
import binascii
import luigi
import traceback
import hashlib
import base64
import logging
import asyncio
import shlex

from luigi.util import inherits
from webcap import Browser
from webcap.errors import WebCapError
from waluigi import scan_utils
from waluigi import data_model


future_map = {}


class Webcap(data_model.WaluigiTool):

    def __init__(self):
        self.name = 'webcap'
        self.description = 'A python library that can be used for taking screenshots of web pages using Chrome and Webcap. Currently only the timeout and threads options can be set.'
        self.project_url = 'https://github.com/blacklanternsecurity/webcap'
        self.collector_type = data_model.CollectorType.ACTIVE.value
        self.scan_order = 8
        self.args = "--timeout 5 --threads 5"
        self.scan_func = Webcap.webcap_scan_func
        self.import_func = Webcap.webcap_import

        # Set logging higher for websockets to avoid too much output
        logging.getLogger("websockets.client").setLevel(logging.WARNING)

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


def parse_args(args_str):
    timeout = 5
    threads = 5
    if args_str and len(args_str) > 0:
        tokens = shlex.split(args_str)
        for i, token in enumerate(tokens):
            if token == "--timeout" and i + 1 < len(tokens):
                try:
                    timeout = int(tokens[i + 1])
                except ValueError:
                    pass
            if token == "--threads" and i + 1 < len(tokens):
                try:
                    threads = int(tokens[i + 1])
                except ValueError:
                    pass
    return timeout, threads


async def webcap_asyncio(future_map, meta_file_path, webcap_args):

    # Get the arguments for timeout and threads
    timeout, threads = parse_args(webcap_args)

    # create a browser instance
    browser = Browser(timeout=timeout, threads=threads)
    # start the browser
    await browser.start()

    with open(meta_file_path, 'w') as f:
        for url, scan_tuple in future_map.items():
            port_id, http_endpoint_data_id, domain_str, path = scan_tuple
            url_entry = {'port_id': port_id,
                         'http_endpoint_data_id': http_endpoint_data_id, 'path': path, 'domain': domain_str}

            # take a screenshot
            webscreenshot = None
            try:
                webscreenshot = await browser.screenshot(url)
            except WebCapError as e:
                logging.getLogger(__name__).error(
                    f"WebCapError, restarting browser: {str(e)}")
                # Restart the browser
                browser = Browser(timeout=timeout, threads=threads)
                await browser.start()
                continue
            except Exception as e:
                logging.getLogger(__name__).error(
                    f"Error taking screenshot for {url}: {str(e)}")
                logging.getLogger(__name__).debug(traceback.format_exc())
                break

            if webscreenshot and webscreenshot.status_code != 0:
                url_entry['url'] = url
                try:
                    url_entry['image_data'] = base64.b64encode(
                        webscreenshot.blob).decode()
                except ValueError as e:
                    # Skip if there is no image data
                    continue
                url_entry['status_code'] = webscreenshot.status_code
                url_entry['title'] = webscreenshot.title

                # Write as JSON line
                f.write(json.dumps(url_entry) + '\n')
            else:
                logging.getLogger(__name__).warning(
                    f"Failed to take screenshot for {url}")

    # stop the browser
    await browser.stop()


def webcap_wrapper(future_map, meta_file_path):

    return asyncio.run(webcap_asyncio(future_map, meta_file_path))


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

        logging.getLogger(__name__).debug(
            "WebcapScan started. Output directory: %s" % dir_path)

        scheduled_scan_obj = self.scan_input

        scope_obj = scheduled_scan_obj.scan_data
        target_map = scope_obj.host_port_obj_map
        http_endpoint_port_id_map = scope_obj.http_endpoint_port_id_map
        web_path_map = scope_obj.path_map
        domain_map = scope_obj.domain_map
        endpoint_data_endpoint_id_map = scope_obj.endpoint_data_endpoint_id_map

        webcap_scan_args = scheduled_scan_obj.current_tool.args

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

                # For hosts without HTTP endpoints, let's try to confirm this is likely a web
                # endpoint so we aren't trying to screencap regular ports
                # First we'll check for the http component, next we'll check if it's port 80 or 443
                likely_http = False
                component_port_id_map = scope_obj.component_port_id_map
                if port_id in component_port_id_map:
                    component_obj_list = component_port_id_map[port_id]
                    for component_obj in component_obj_list:
                        component_name = component_obj.name
                        if 'http' in component_name.lower():
                            likely_http = True
                            break

                if port_str in ['80', '443']:
                    likely_http = True

                # Queue if it is likely an HTTP endpoint
                if likely_http:
                    queue_scan(ip_addr, port_str, secure, port_id,
                               query_arg, domain_str_orig)

                    # Add for domains in the scope
                    if host_id in scope_obj.domain_host_id_map:
                        temp_domain_list = scope_obj.domain_host_id_map[host_id]
                        for domain_obj in temp_domain_list:

                            domain_name = domain_obj.name
                            queue_scan(domain_name, port_str, secure,
                                       port_id, query_arg, domain_name)
                else:
                    logging.getLogger(__name__).debug(
                        "Skipping port %s on host %s as it does not appear to be a web endpoint." % (port_str, ip_addr))

        # Submit the scan task
        meta_file = '%s%s%s' % (dir_path, os.path.sep, 'screenshots.json')
        future_inst = scan_utils.executor.submit(
            webcap_wrapper, future_map, meta_file)

        scan_proc_inst = data_model.ToolExecutor([future_inst])
        scheduled_scan_obj.register_tool_executor(
            scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

        # Wait for the tasks to complete and retrieve results
        future_inst.result()


@inherits(WebcapScan)
class ImportWebcapOutput(data_model.ImportToolXOutput):

    def requires(self):
        # Requires WebcapScan Task to be run prior
        return WebcapScan(scan_input=self.scan_input)

    def run(self):

        meta_file = self.input().path
        scheduled_scan_obj = self.scan_input
        tool_instance_id = scheduled_scan_obj.current_tool_instance_id
        scan_id = scheduled_scan_obj.scan_id
        recon_manager = scheduled_scan_obj.scan_thread.recon_manager
        tool_obj = scheduled_scan_obj.current_tool
        tool_id = tool_obj.id

        path_hash_map = {}
        screenshot_hash_map = {}
        domain_name_id_map = {}

        if os.path.exists(meta_file):

            with open(meta_file, 'r') as file_fd:

                count = 0
                for line in file_fd:
                    if not line.strip():
                        continue

                    ret_arr = []
                    screenshot_meta = json.loads(line)
                    import_data_arr = []

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
                        screenshot_obj.collection_tool_instance_id = tool_instance_id
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
                            domain_obj.collection_tool_instance_id = tool_instance_id
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
                        path_obj.collection_tool_instance_id = tool_instance_id
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
                    http_endpoint_obj.collection_tool_instance_id = tool_instance_id
                    http_endpoint_obj.web_path_id = web_path_id

                    # Add the endpoint
                    ret_arr.append(http_endpoint_obj)

                    # Add http endpoint data
                    http_endpoint_data_obj = data_model.HttpEndpointData(
                        parent_id=http_endpoint_obj.id)
                    http_endpoint_data_obj.collection_tool_instance_id = tool_instance_id
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
