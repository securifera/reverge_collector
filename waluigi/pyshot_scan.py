"""
Pyshot Screenshot Capture Module.

This module provides comprehensive web page screenshot capabilities using Pyshot,
a Python library that leverages PhantomJS for automated web page rendering and
image capture. It integrates with the Waluigi framework to perform automated
screenshot collection of discovered web endpoints.

The module supports:
    - Automated screenshot capture of web pages and endpoints
    - Support for both HTTP and HTTPS targets
    - Domain-based and IP-based screenshot collection
    - Concurrent screenshot processing for performance
    - Base64 image encoding and hash-based deduplication
    - Integration with HTTP endpoint discovery results

Classes:
    Pyshot: Main tool class implementing the screenshot capture interface
    PyshotScan: Luigi task for executing screenshot capture operations
    ImportPyshotOutput: Luigi task for importing and processing screenshot results

Functions:
    pyshot_wrapper: Core screenshot capture function using pyshot library
    queue_scan: Manages screenshot target queuing with deduplication

Global Variables:
    future_map: Thread-safe mapping for tracking queued screenshot targets

Example:
    Basic usage through the Waluigi framework::
    
        # Initialize the tool
        pyshot = Pyshot()
        
        # Execute screenshot capture
        success = pyshot.scan_func(scan_input_obj)
        
        # Import results
        imported = pyshot.import_func(scan_input_obj)

Note:
    This module requires PhantomJS to be installed and accessible in the system PATH.
    The tool performs active web requests and should be used responsibly with proper
    authorization on target systems.

"""

import json
import os
import binascii
import traceback
import hashlib
import base64
import logging
from typing import Dict, Tuple, Any, Optional, List

from waluigi import scan_utils
from os.path import exists
from waluigi import data_model
from waluigi.tool_spec import ToolSpec

# Global future mapping for screenshot target management and deduplication
future_map: Dict[str, Tuple[Optional[int], Tuple]] = {}


class Pyshot(ToolSpec):

    name = 'pyshot'
    description = 'A python library that can be used for taking screenshots of web pages using PhantomJS.'
    project_url = 'https://github.com/securifera/pyshot'
    tags = ['screenshot', 'load-balancer-incompatible']
    collector_type = data_model.CollectorType.ACTIVE.value
    scan_order = 8
    args = ''
    input_records = [data_model.ServerRecordType.PORT,
                     data_model.ServerRecordType.HTTP_ENDPOINT_DATA]
    output_records = [
        data_model.ServerRecordType.SCREENSHOT,
        data_model.ServerRecordType.DOMAIN,
        data_model.ServerRecordType.LIST_ITEM,
        data_model.ServerRecordType.HTTP_ENDPOINT,
        data_model.ServerRecordType.HTTP_ENDPOINT_DATA,
    ]

    def get_output_path(self, scan_input) -> str:
        return get_output_path(scan_input)

    def execute_scan(self, scan_input) -> None:
        execute_scan(scan_input)

    def parse_output(self, output_path: str, scan_input) -> list:
        return parse_pyshot_output(
            output_path,
            scan_input.current_tool_instance_id,
        ) or []


def pyshot_wrapper(ip_addr: str, port: str, dir_path: str, ssl_val: bool, port_id: int,
                   query_arg: str = "", domain: Optional[str] = None,
                   http_endpoint_data_id: Optional[int] = None) -> str:
    """
    Wrapper function for executing Pyshot screenshot capture operations.

    This function provides a standardized interface for capturing screenshots
    of web endpoints using the Pyshot library. It handles the configuration
    and execution of screenshot capture with appropriate logging and error handling.

    Args:
        ip_addr (str): The target IP address or hostname
        port (str): The target port number as a string
        dir_path (str): Directory path where screenshots will be saved
        ssl_val (bool): Whether to use HTTPS (True) or HTTP (False)
        port_id (int): Database identifier for the target port
        query_arg (str, optional): URL path/query string to append. Defaults to "".
        domain (str, optional): Domain name to use instead of IP. Defaults to None.
        http_endpoint_data_id (int, optional): Database ID for endpoint data. Defaults to None.

    Returns:
        str: Status message from the screenshot operation (typically empty)

    Side Effects:
        - Creates screenshot files in the specified directory
        - Generates metadata files for screenshot import
        - Logs debug information about the screenshot operation

    Example:
        >>> result = pyshot_wrapper(
        ...     "192.168.1.1", "80", "/tmp/screenshots", False, 123,
        ...     query_arg="/admin", domain="example.com"
        ... )
        >>> print("Screenshot capture completed")

    Note:
        The function uses the pyshot library's take_screenshot method internally.
        SSL certificate validation is typically disabled for broader compatibility.
    """

    ret_msg = ""
    domain_str = ''
    if domain:
        domain_str = domain
    logging.getLogger(__name__).debug("Running Pyshot scan on %s:%s%s (%s)" %
                                      (ip_addr, port, query_arg, domain_str))
    from pyshot import pyshot as pyshot_lib  # noqa: PLC0415
    pyshot_lib.take_screenshot(host=ip_addr, port_arg=port, query_arg=query_arg,
                               dest_dir=dir_path, secure=ssl_val, port_id=port_id, domain=domain, endpoint_id=http_endpoint_data_id)

    return ret_msg


def queue_scan(host: str, port_str: str, dir_path: str, secure: bool, port_id: int,
               query_arg: str = "", domain_str: Optional[str] = None,
               http_endpoint_data_id: Optional[int] = None) -> None:
    """
    Queue a screenshot capture target with deduplication and priority management.

    This function manages the queuing of screenshot targets while preventing
    duplicates and handling priority-based updates. It maintains a global mapping
    of URLs to their associated screenshot tasks and metadata.

    Args:
        host (str): The target host (IP address or hostname)
        port_str (str): The target port number as a string
        dir_path (str): Directory path where screenshots will be saved
        secure (bool): Whether to use HTTPS (True) or HTTP (False)
        port_id (int): Database identifier for the target port
        query_arg (str, optional): URL path/query string to append. Defaults to "".
        domain_str (str, optional): Domain name for the target. Defaults to None.
        http_endpoint_data_id (int, optional): Database ID for endpoint data. Defaults to None.

    Returns:
        None: This function modifies the global future_map dictionary in-place

    Side Effects:
        - Modifies the global future_map to track queued screenshot targets
        - Implements priority-based replacement for existing targets
        - Constructs URLs for deduplication purposes

    Example:
        >>> queue_scan("192.168.1.1", "80", "/tmp/screenshots", False, 123,
        ...           query_arg="/login", domain_str="example.com")
        >>> # Target is now queued for screenshot capture

    Note:
        If a URL is already queued and the new request has an endpoint data ID
        while the existing one doesn't, the new request takes priority.
        This ensures more specific endpoint data is preserved.
    """

    global future_map

    target_str = host
    if domain_str:
        target_str = domain_str

    url = scan_utils.construct_url(target_str, port_str, secure, query_arg)
    if url is None:
        return
    if url in future_map:
        prev_http_endpoint_data_id, scan_tuple = future_map[url]
        # the previous http endoint is None then switch it out to avoid duplicates
        if http_endpoint_data_id is not None and prev_http_endpoint_data_id is None:
            scan_tuple = (pyshot_wrapper, host, port_str, dir_path, secure,
                          port_id, query_arg, domain_str, http_endpoint_data_id)
            future_map[url] = (http_endpoint_data_id, scan_tuple)
            return

    else:
        scan_tuple = (pyshot_wrapper, host, port_str, dir_path, secure,
                      port_id, query_arg, domain_str, http_endpoint_data_id)
        future_map[url] = (http_endpoint_data_id, scan_tuple)

    return


def get_output_path(scan_input) -> str:
    scan_id = scan_input.id
    tool_name = scan_input.current_tool.name
    dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)
    return dir_path + os.path.sep + 'screenshots.meta'


def execute_scan(scan_input) -> None:
    output_file_path = get_output_path(scan_input)
    if os.path.exists(output_file_path):
        return

    global future_map
    dir_path = os.path.dirname(output_file_path)

    scheduled_scan_obj = scan_input
    url_metadata_map = scheduled_scan_obj.scan_data.get_urls()

    from urllib.parse import urlparse
    futures = []

    for url, metadata in url_metadata_map.items():
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port_str = str(parsed_url.port) if parsed_url.port else (
            '443' if parsed_url.scheme == 'https' else '80')
        secure = parsed_url.scheme == 'https'
        query_arg = parsed_url.path + \
            ('?' + parsed_url.query if parsed_url.query else '')

        future_inst = scan_utils.executor.submit(
            pyshot_wrapper, host, port_str, dir_path, secure,
            metadata["port_id"], query_arg, metadata.get("domain"),
            metadata.get("http_endpoint_data_id"))
        futures.append(future_inst)

    scan_proc_inst = data_model.ToolExecutor(futures)
    scheduled_scan_obj.register_tool_executor(
        scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

    for future in futures:
        future.result()


def parse_pyshot_output(meta_file, tool_instance_id):
    """Parse a Pyshot .meta file and return a flat list of data-model objects."""
    ret_arr = []
    if not os.path.exists(meta_file):
        return ret_arr

    path_hash_map = {}
    screenshot_hash_map = {}
    domain_name_id_map = {}
    hash_alg = hashlib.sha1

    with open(meta_file, 'r') as file_fd:
        lines = file_fd.readlines()

    for line in lines:
        screenshot_meta = json.loads(line)
        filename = screenshot_meta['file_path']
        if not (filename and exists(filename)):
            continue

        web_path = screenshot_meta['path']
        port_id = screenshot_meta['port_id']
        status_code = screenshot_meta['status_code']
        http_endpoint_data_id = screenshot_meta['endpoint_id']

        with open(filename, "rb") as rf:
            image_data = rf.read()
        hashobj = hash_alg()
        hashobj.update(image_data)
        image_hash_str = binascii.hexlify(hashobj.digest()).decode()
        screenshot_bytes_b64 = base64.b64encode(image_data).decode()

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

        hashobj = hash_alg()
        hashobj.update(web_path.encode())
        web_path_hash = binascii.hexlify(hashobj.digest()).decode()

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
            ret_arr.append(domain_obj)
            endpoint_domain_id = domain_obj.id

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

        http_endpoint_obj = data_model.HttpEndpoint(parent_id=port_id)
        http_endpoint_obj.collection_tool_instance_id = tool_instance_id
        http_endpoint_obj.web_path_id = web_path_id
        ret_arr.append(http_endpoint_obj)

        http_endpoint_data_obj = data_model.HttpEndpointData(
            parent_id=http_endpoint_obj.id)
        http_endpoint_data_obj.collection_tool_instance_id = tool_instance_id
        http_endpoint_data_obj.domain_id = endpoint_domain_id
        http_endpoint_data_obj.status = status_code
        http_endpoint_data_obj.screenshot_id = screenshot_id
        if http_endpoint_data_id:
            http_endpoint_data_obj.id = http_endpoint_data_id
        ret_arr.append(http_endpoint_data_obj)

    return ret_arr


def pyshot_scan_func(scan_input) -> bool:
    try:
        execute_scan(scan_input)
        return True
    except Exception as e:
        logging.getLogger(__name__).error(
            "pyshot scan failed: %s", e, exc_info=True)
        raise


def pyshot_import(scan_input) -> bool:
    try:
        output_path = get_output_path(scan_input)
        if not os.path.exists(output_path):
            return True
        if _import_already_done(scan_input, output_path):
            return True
        tool_instance_id = scan_input.current_tool_instance_id
        ret_arr = parse_pyshot_output(output_path, tool_instance_id)
        if ret_arr:
            _import_results(scan_input, ret_arr, output_path)
        return True
    except Exception as e:
        logging.getLogger(__name__).error(
            "pyshot import failed: %s", e, exc_info=True)
        raise
