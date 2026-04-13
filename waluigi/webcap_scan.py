"""
Webcap Screenshot Capture Module.

This module provides comprehensive web page screenshot capabilities using Webcap,
a Python library that leverages Chrome/Chromium for automated web page rendering
and high-quality image capture. It integrates with the Waluigi framework to perform
automated screenshot collection of discovered web endpoints with advanced features.

The module supports:
    - High-quality Chrome-based screenshot capture
    - Asynchronous concurrent processing for performance
    - Configurable timeout, thread count, and image quality settings
    - Support for both HTTP and HTTPS targets with custom headers
    - Domain-based and IP-based screenshot collection
    - Advanced error handling and browser restart capabilities
    - Base64 image encoding and hash-based deduplication
    - Integration with HTTP endpoint discovery results

Classes:
    Webcap: Main tool class implementing the Chrome-based screenshot interface
    WebcapScan: Luigi task for executing screenshot capture operations
    ImportWebcapOutput: Luigi task for importing and processing screenshot results

Functions:
    parse_args: Parses command-line arguments for Webcap configuration
    webcap_asyncio: Asynchronous screenshot capture using Chrome browser
    webcap_wrapper: Synchronous wrapper for async screenshot operations
    queue_scan: Manages screenshot target queuing with deduplication

Global Variables:
    future_map: Thread-safe mapping for tracking queued screenshot targets

Example:
    Basic usage through the Waluigi framework::
    
        # Initialize the tool
        webcap = Webcap()
        
        # Execute screenshot capture
        success = webcap.scan_func(scan_input_obj)
        
        # Import results
        imported = webcap.import_func(scan_input_obj)

Note:
    This module requires Chrome/Chromium to be installed and accessible.
    The tool performs active web requests and should be used responsibly with proper
    authorization on target systems. Webcap provides superior performance and
    quality compared to PhantomJS-based solutions.

"""

import json
import os
import binascii
import traceback
import hashlib
import base64
import logging
import asyncio
import math
import shlex
from typing import Dict, Tuple, Any, Optional, List

from waluigi import scan_utils
from waluigi import data_model
from waluigi.tool_spec import ToolSpec

# Global future mapping for screenshot target management and deduplication
future_map: Dict[str, Tuple[int, Optional[int], Optional[str], str]] = {}


class Webcap(ToolSpec):

    name = 'webcap'
    description = 'A python library that can be used for taking screenshots of web pages using Chrome and Webcap. Currently only the timeout and threads options can be set.'
    project_url = 'https://github.com/blacklanternsecurity/webcap'
    tags = ['screenshot', 'load-balancer-compatible']
    collector_type = data_model.CollectorType.ACTIVE.value
    scan_order = 8
    args = '--timeout 5 --threads 5 --quality 20 --format jpeg'
    input_records = [data_model.ServerRecordType.PORT,
                     data_model.ServerRecordType.HTTP_ENDPOINT_DATA]
    output_records = [
        data_model.ServerRecordType.SCREENSHOT,
        data_model.ServerRecordType.DOMAIN,
        data_model.ServerRecordType.LIST_ITEM,
        data_model.ServerRecordType.HTTP_ENDPOINT,
        data_model.ServerRecordType.HTTP_ENDPOINT_DATA,
    ]

    def __init__(self):
        super().__init__()
        # Suppress verbose websocket/httpcore output
        logging.getLogger('websockets.client').setLevel(logging.WARNING)
        logging.getLogger('httpcore.http11').setLevel(logging.WARNING)
        logging.getLogger('httpcore.connection').setLevel(logging.WARNING)

    def get_output_path(self, scan_input) -> str:
        return get_output_path(scan_input)

    def execute_scan(self, scan_input) -> None:
        execute_scan(scan_input)

    def parse_output(self, output_path: str, scan_input) -> list:
        return parse_webcap_output(
            output_path,
            scan_input.current_tool_instance_id,
        ) or []


def parse_args(args_str: str) -> Tuple[int, int, int]:
    """
    Parse command-line arguments for Webcap configuration.

    This function extracts timeout, thread count, and quality settings from
    a command-line argument string, providing defaults for any missing values.
    It uses shell-like parsing to handle quoted arguments properly.

    Args:
        args_str (str): Command-line argument string containing Webcap parameters.
                       Expected format: "--timeout 5 --threads 5 --quality 100"

    Returns:
        Tuple[int, int, int]: A tuple containing (timeout, threads, quality)
                             where timeout is in seconds, threads is the concurrent
                             browser count, and quality is image quality percentage

    Example:
        >>> timeout, threads, quality = parse_args("--timeout 10 --threads 3 --quality 90")
        >>> print(f"Config: {timeout}s timeout, {threads} threads, {quality}% quality")
        Config: 10s timeout, 3 threads, 90% quality

        >>> # With defaults for missing values
        >>> timeout, threads, quality = parse_args("--timeout 15")
        >>> print(f"Config: {timeout}s timeout, {threads} threads, {quality}% quality")
        Config: 15s timeout, 5 threads, 100% quality

    Note:
        Default values are: timeout=5, threads=5, quality=100
        Invalid numeric values are silently ignored and defaults are used.
        Uses shlex.split() for proper shell-like argument parsing.
    """
    timeout = 5
    threads = 5
    quality = 100
    image_format = "jpeg"
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
            if token == "--quality" and i + 1 < len(tokens):
                try:
                    quality = int(tokens[i + 1])
                    # Ensure quality is between 1 and 100
                    quality = max(1, min(quality, 100))
                except ValueError:
                    pass
            if token == "--format" and i + 1 < len(tokens):
                tmp_format = tokens[i + 1]
                # Ensure image format is one of the supported types jpeg, png, webp
                if tmp_format in ["jpeg", "png", "webp"]:
                    image_format = tmp_format

    return timeout, threads, image_format, quality


async def webcap_asyncio(future_map: Dict[str, Tuple], meta_file_path: str,
                         webcap_args: str) -> None:
    """
    Asynchronous Chrome-based screenshot capture operation.

    This async function manages the complete Chrome browser lifecycle and screenshot
    capture process. It handles browser initialization, concurrent screenshot capture,
    error recovery with browser restart, and metadata file generation.

    Args:
        future_map (Dict[str, Tuple]): Mapping of URLs to screenshot target metadata
                                      containing port_id, endpoint_id, domain, and path
        meta_file_path (str): File path where screenshot metadata will be written
        webcap_args (str): Command-line arguments for Webcap configuration

    Returns:
        None: Screenshots and metadata are written to files during execution

    Side Effects:
        - Creates and manages Chrome browser instances
        - Captures screenshots and saves metadata to JSON line format
        - Handles browser restarts on WebCapError exceptions
        - Logs errors and warnings for failed screenshot attempts

    Raises:
        WebCapError: Handled internally with browser restart
        Exception: Various exceptions related to screenshot capture or file I/O

    Example:
        >>> target_map = {"https://example.com": (123, 456, "example.com", "/")}
        >>> await webcap_asyncio(target_map, "/tmp/screenshots.json", "--timeout 10")

    Note:
        The function implements automatic browser restart on WebCapError to handle
        Chrome crashes or unresponsive states. Each screenshot includes URL, image
        data (Base64), status code, title, and associated metadata.
    """

    # Get the arguments for timeout and threads
    timeout, threads, image_format, quality = parse_args(webcap_args)

    from webcap import Browser  # noqa: PLC0415
    from webcap.errors import WebCapError  # noqa: PLC0415

    # create a browser instance
    browser = Browser(timeout=timeout, threads=threads,
                      image_format=image_format, quality=quality)
    # start the browser
    await browser.start()

    try:
        with open(meta_file_path, 'w') as f:
            for url, scan_tuple in future_map.items():
                port_id, http_endpoint_data_id, domain_str, path = scan_tuple
                url_entry = {'port_id': port_id,
                             'http_endpoint_data_id': http_endpoint_data_id, 'path': path, 'domain': domain_str}

                async def _restart_browser():
                    nonlocal browser
                    try:
                        await browser.stop()
                    except Exception:
                        pass
                    browser = Browser(timeout=timeout, threads=threads,
                                      image_format=image_format, quality=quality)
                    await browser.start()
                    # Brief pause to let Chrome fully initialise before the
                    # next request
                    await asyncio.sleep(1)

                # Take a screenshot, retrying once if the browser session is
                # broken (WebCapError).  Using a retry avoids silently
                # dropping the URL that triggered the restart.
                webscreenshot = None
                for _attempt in range(2):
                    try:
                        webscreenshot = await browser.screenshot(url)
                        break
                    except WebCapError as e:
                        logging.getLogger(__name__).error(
                            f"WebCapError (attempt {_attempt + 1}), restarting browser: {str(e)}")
                        await _restart_browser()
                        if _attempt == 1:
                            logging.getLogger(__name__).warning(
                                f"Skipping {url} after two browser restart attempts")
                    except Exception as e:
                        logging.getLogger(__name__).error(
                            f"Error taking screenshot for {url}: {str(e)}")
                        logging.getLogger(__name__).debug(
                            traceback.format_exc())
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

                if browser.orphaned_session:
                    logging.getLogger(__name__).debug(
                        "Orphaned session detected. Restarting")
                    await _restart_browser()

    finally:
        # Ensure browser is always stopped, even if there are errors
        await browser.stop()


def webcap_wrapper(future_map: Dict[str, Tuple], meta_file_path: str,
                   webcap_scan_args: str) -> Any:
    """
    Synchronous wrapper for asynchronous Webcap screenshot operations.

    This function provides a synchronous interface to the asynchronous Webcap
    screenshot capture functionality, enabling integration with synchronous
    workflow systems while maintaining the performance benefits of async operations.

    Args:
        future_map (Dict[str, Tuple]): Mapping of URLs to screenshot target metadata
        meta_file_path (str): File path where screenshot metadata will be written
        webcap_scan_args (str): Command-line arguments for Webcap configuration

    Returns:
        Any: The result of the async operation (typically None)

    Example:
        >>> target_map = {"https://example.com": (123, 456, "example.com", "/")}
        >>> result = webcap_wrapper(target_map, "/tmp/screenshots.json", "--timeout 10")

    Note:
        Uses asyncio.run() to execute the async screenshot capture in a new
        event loop. This allows the function to be called from synchronous
        code while maintaining async performance benefits.
    """

    return asyncio.run(webcap_asyncio(future_map, meta_file_path, webcap_scan_args))


def get_output_path(scan_input) -> str:
    scan_id = scan_input.id
    tool_name = scan_input.current_tool.name
    dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)
    return dir_path + os.path.sep + 'screenshots.json'


def execute_scan(scan_input) -> None:
    output_file_path = get_output_path(scan_input)
    if os.path.exists(output_file_path):
        return

    global future_map
    dir_path = os.path.dirname(output_file_path)

    logging.getLogger(__name__).debug(
        "WebcapScan started. Output directory: %s" % dir_path)

    scheduled_scan_obj = scan_input
    webcap_scan_args = scheduled_scan_obj.current_tool.args

    future_map = {}
    url_metadata_map = scheduled_scan_obj.scan_data.get_urls()

    for url, metadata in url_metadata_map.items():
        scan_tuple = (
            metadata["port_id"],
            metadata.get("http_endpoint_data_id"),
            metadata.get("domain"),
            metadata["path"]
        )
        future_map[url] = scan_tuple

    future_inst = scan_utils.executor.submit(
        webcap_wrapper, future_map, output_file_path, webcap_scan_args)

    scan_proc_inst = data_model.ToolExecutor([future_inst])
    scheduled_scan_obj.register_tool_executor(
        scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

    # Derive a wall-clock timeout so we never hang indefinitely.
    # Formula: ceil(urls / threads) * per_page_timeout * 3  (3× overhead for
    # browser startup / slow pages), with a minimum of 60 s.
    per_page_timeout, threads, _, _ = parse_args(webcap_scan_args)
    url_count = len(future_map)
    batches = math.ceil(url_count / threads) if url_count and threads else 1
    wall_timeout = max(batches * per_page_timeout * 3, 60)

    try:
        future_inst.result(timeout=wall_timeout)
    except TimeoutError:
        logging.getLogger(__name__).warning(
            "WebcapScan timed out after %ds (%d URLs, %d threads, %ds/page)",
            wall_timeout, url_count, threads, per_page_timeout,
        )


def parse_webcap_output(meta_file, tool_instance_id):
    """Parse a Webcap JSON-lines metadata file and return data-model objects."""
    ret_arr = []
    if not os.path.exists(meta_file):
        return ret_arr

    path_hash_map = {}
    screenshot_hash_map = {}
    domain_name_id_map = {}

    with open(meta_file, 'r') as file_fd:
        for line in file_fd:
            if not line.strip():
                continue

            screenshot_meta = json.loads(line)
            web_path = screenshot_meta['path']
            port_id = screenshot_meta['port_id']
            status_code = screenshot_meta['status_code']
            screenshot_bytes_b64 = screenshot_meta['image_data']
            title = screenshot_meta['title']
            http_endpoint_data_id = screenshot_meta['http_endpoint_data_id']

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
                screenshot_hash_map[image_hash_str] = screenshot_obj

            ret_arr.append(screenshot_obj)
            screenshot_id = screenshot_obj.id

            hashobj = hash_alg()
            hashobj.update(web_path.encode())
            path_hash = hashobj.digest()
            web_path_hash = binascii.hexlify(path_hash).decode()

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
            http_endpoint_data_obj.title = title
            http_endpoint_data_obj.screenshot_id = screenshot_id
            if http_endpoint_data_id:
                http_endpoint_data_obj.id = http_endpoint_data_id
            ret_arr.append(http_endpoint_data_obj)

    return ret_arr
