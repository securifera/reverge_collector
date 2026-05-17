"""
Webcap Screenshot Capture Module.

This module provides comprehensive web page screenshot capabilities using Webcap,
a Python library that leverages Chrome/Chromium for automated web page rendering
and high-quality image capture. It integrates with the reverge_collector framework to perform
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
    Basic usage through the reverge_collector framework::

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

import asyncio
import base64
import binascii
import hashlib
import json
import logging
import os
import shlex
import traceback
from typing import Any, Dict, Optional, Tuple

from reverge_collector import data_model, scan_utils
from reverge_collector.tool_spec import ToolSpec

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
    input_records = [
        data_model.ServerRecordType.PORT,
        data_model.ServerRecordType.HTTP_ENDPOINT_DATA,
        data_model.ServerRecordType.SUBNET,
    ]
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
        return (
            parse_webcap_output(
                output_path,
                scan_input.current_tool_instance_id,
            )
            or []
        )


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
    image_format = 'jpeg'
    if args_str and len(args_str) > 0:
        tokens = shlex.split(args_str)
        for i, token in enumerate(tokens):
            if token == '--timeout' and i + 1 < len(tokens):
                try:
                    timeout = int(tokens[i + 1])
                except ValueError:
                    pass
            if token == '--threads' and i + 1 < len(tokens):
                try:
                    threads = int(tokens[i + 1])
                except ValueError:
                    pass
            if token == '--quality' and i + 1 < len(tokens):
                try:
                    quality = int(tokens[i + 1])
                    # Ensure quality is between 1 and 100
                    quality = max(1, min(quality, 100))
                except ValueError:
                    pass
            if token == '--format' and i + 1 < len(tokens):
                tmp_format = tokens[i + 1]
                # Ensure image format is one of the supported types jpeg, png, webp
                if tmp_format in ['jpeg', 'png', 'webp']:
                    image_format = tmp_format

    return timeout, threads, image_format, quality


async def webcap_asyncio(
    future_map: Dict[str, Tuple], meta_file_path: str, webcap_args: str
) -> None:
    """
    Asynchronous Chrome-based screenshot capture with graduated recovery.

    Recovery strategy (cheapest first, restart is last resort):
      1. Per-screenshot wall timeout bounds hangs that slip past webcap's
         internal per-CDP-command timeouts.
      2. On WebCapError, timeout, or an orphaned-session flag, call
         ``browser.force_target_cleanup()`` to close stale page targets in
         place. This keeps the same Chrome process and avoids the Linux
         login-keyring prompt that fires on every Chrome (re)launch.
      3. Only after ``CONSECUTIVE_FAILURE_RESTART_THRESHOLD`` consecutive
         failures do we tear down and relaunch Chrome — at that point the
         process is presumed wedged.
    """

    timeout, threads, image_format, quality = parse_args(webcap_args)

    from webcap import Browser  # noqa: PLC0415
    from webcap.errors import WebCapError  # noqa: PLC0415

    log = logging.getLogger(__name__)

    # Per-screenshot wall ceiling. Webcap already bounds each individual CDP
    # request at ``timeout`` seconds; this covers the full open-tab/navigate/
    # capture/close pipeline (~3 CDP round-trips worst case) with headroom.
    per_screenshot_wall = max(timeout * 4, 30)
    # How many back-to-back failures justify a full Chrome restart.
    CONSECUTIVE_FAILURE_RESTART_THRESHOLD = 5

    browser = Browser(timeout=timeout, threads=threads, image_format=image_format, quality=quality)
    await browser.start()

    consecutive_failures = 0

    async def _light_recovery(reason: str) -> None:
        """In-process cleanup — no Chrome restart, no keyring popup."""
        log.debug('Light recovery (%s): force_target_cleanup', reason)
        try:
            await browser.force_target_cleanup()
        except Exception as e:
            log.warning('force_target_cleanup failed (%s): %s', reason, e)

    async def _restart_browser(reason: str) -> None:
        nonlocal browser, consecutive_failures
        log.warning(
            'Restarting Chrome (%s) after %d consecutive failures', reason, consecutive_failures
        )
        try:
            await browser.stop()
        except Exception:
            pass
        browser = Browser(
            timeout=timeout, threads=threads, image_format=image_format, quality=quality
        )
        await browser.start()
        consecutive_failures = 0
        # Brief settle so the next request doesn't race the message handler.
        await asyncio.sleep(1)

    try:
        with open(meta_file_path, 'w') as f:
            for url, scan_tuple in future_map.items():
                port_id, http_endpoint_data_id, domain_str, path = scan_tuple
                url_entry = {
                    'port_id': port_id,
                    'http_endpoint_data_id': http_endpoint_data_id,
                    'path': path,
                    'domain': domain_str,
                }

                webscreenshot = None
                for _attempt in range(2):
                    try:
                        webscreenshot = await asyncio.wait_for(
                            browser.screenshot(url),
                            timeout=per_screenshot_wall,
                        )
                        break
                    except asyncio.TimeoutError:
                        log.warning(
                            'Screenshot %s exceeded %ds wall timeout (attempt %d)',
                            url,
                            per_screenshot_wall,
                            _attempt + 1,
                        )
                        await _light_recovery('screenshot wall timeout')
                    except WebCapError as e:
                        log.error('WebCapError on %s (attempt %d): %s', url, _attempt + 1, e)
                        await _light_recovery('WebCapError')
                    except Exception as e:
                        log.error('Error taking screenshot for %s: %s', url, e)
                        log.debug(traceback.format_exc())
                        break

                if webscreenshot and webscreenshot.status_code != 0:
                    consecutive_failures = 0
                    url_entry['url'] = url
                    try:
                        url_entry['image_data'] = base64.b64encode(webscreenshot.blob).decode()
                    except ValueError:
                        continue
                    url_entry['status_code'] = webscreenshot.status_code
                    url_entry['title'] = webscreenshot.title
                    f.write(json.dumps(url_entry) + '\n')
                else:
                    consecutive_failures += 1
                    log.warning('Failed to take screenshot for %s', url)

                # Orphan flag is mostly benign post-close event-race noise
                # (handled inside webcap); when it does fire, drain the
                # straggler targets in place rather than restarting Chrome.
                if browser.orphaned_session:
                    log.debug('Orphaned session flag set; running light recovery')
                    await _light_recovery('orphan flag')

                # Escalate to a full restart only when Chrome appears truly
                # wedged — many URLs in a row failing.
                if consecutive_failures >= CONSECUTIVE_FAILURE_RESTART_THRESHOLD:
                    await _restart_browser('consecutive-failure threshold')

    finally:
        try:
            await browser.stop()
        except Exception:
            pass


def webcap_wrapper(future_map: Dict[str, Tuple], meta_file_path: str, webcap_scan_args: str) -> Any:
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
        logging.getLogger(__name__).debug(
            'Output path %s already exists, skipping Webcap scan execution', output_file_path
        )
        return

    global future_map
    dir_path = os.path.dirname(output_file_path)

    logging.getLogger(__name__).debug('WebcapScan started. Output directory: %s' % dir_path)

    scheduled_scan_obj = scan_input
    webcap_scan_args = scheduled_scan_obj.current_tool.args

    future_map = {}
    url_metadata_map = scheduled_scan_obj.scan_data.get_url_metadata_map()

    for url, metadata in url_metadata_map.items():
        scan_tuple = (
            metadata['port_id'],
            metadata.get('http_endpoint_data_id'),
            metadata.get('domain'),
            metadata['path'],
        )
        future_map[url] = scan_tuple

    future_inst = scan_utils.executor.submit(
        webcap_wrapper, future_map, output_file_path, webcap_scan_args
    )

    scan_proc_inst = data_model.ToolExecutor([future_inst])
    scheduled_scan_obj.register_tool_executor(
        scheduled_scan_obj.current_tool_instance_id, scan_proc_inst
    )

    # Derive a wall-clock timeout so we never hang indefinitely. The inner
    # loop processes URLs sequentially (the --threads value is forwarded to
    # webcap but the recovery-aware loop intentionally walks one URL at a
    # time so per-URL recovery is deterministic). Per URL the worst case is
    # the per-screenshot wall ceiling (max(timeout*4, 30)) × 2 attempts,
    # plus occasional Chrome restarts (~5s each, capped at 1 per N URLs).
    per_page_timeout, threads, _, _ = parse_args(webcap_scan_args)
    url_count = len(future_map)
    per_url_wall = max(per_page_timeout * 4, 30)
    restart_budget = max(url_count // 5, 1) * 10  # ~10s amortised per restart
    wall_timeout = max(url_count * per_url_wall * 2 + restart_budget, 60)

    try:
        future_inst.result(timeout=wall_timeout)
    except TimeoutError:
        logging.getLogger(__name__).warning(
            'WebcapScan timed out after %ds (%d URLs, %d threads, %ds/page)',
            wall_timeout,
            url_count,
            threads,
            per_page_timeout,
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

            http_endpoint_data_obj = data_model.HttpEndpointData(parent_id=http_endpoint_obj.id)
            http_endpoint_data_obj.collection_tool_instance_id = tool_instance_id
            http_endpoint_data_obj.domain_id = endpoint_domain_id
            http_endpoint_data_obj.status = status_code
            http_endpoint_data_obj.title = title
            http_endpoint_data_obj.screenshot_id = screenshot_id
            if http_endpoint_data_id:
                http_endpoint_data_obj.id = http_endpoint_data_id
            ret_arr.append(http_endpoint_data_obj)

    return ret_arr
