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
import collections
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
    # Screenshot output embeds large base64 blobs, so import it in bounded
    # batches and drop the raw JSON-lines file once it's been imported (the
    # same data is already persisted server-side).
    streaming_import = True
    delete_output_after_import = True
    # Source lines (one screenshot each) imported per POST.
    import_batch_size = 25

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

    def iter_parsed_batches(self, output_path: str, scan_input):
        yield from iter_webcap_batches(
            output_path,
            scan_input.current_tool_instance_id,
            self.import_batch_size,
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
    Asynchronous Chrome-based screenshot capture.

    Up to ``--threads`` URLs are captured at once, each in its own tab of one
    shared Chrome. A failure on one URL never touches the tabs of the others.

    Recovery (cheapest first, a restart is the last resort):
      1. Each screenshot has a wall timeout, for hangs that slip past
         webcap's own per-request timeouts. A URL that errors is retried once.
      2. When the orphan flag is set, ``browser.force_target_cleanup()``
         closes stray pages (popups, tabs whose close never went through).
         It leaves tabs that are in use alone.
      3. When failures pile up with no success in between, Chrome is asked a
         trivial question. If it answers, the failures are the targets' doing
         (dead hosts time out too) and only strays are swept. If it doesn't,
         Chrome is wedged and gets restarted.
      4. A Chrome that is no longer running at all (``browser.is_alive``) is
         replaced immediately. URLs that were in flight when it died are
         retried one at a time, with nothing else running: the ones that were
         bystanders succeed, and the one that kills Chrome (if any) is
         dropped without taking the others down again.
    """

    timeout, threads, image_format, quality = parse_args(webcap_args)
    threads = max(threads, 1)

    from webcap import Browser  # noqa: PLC0415
    from webcap.errors import WebCapError  # noqa: PLC0415

    log = logging.getLogger(__name__)

    # Per-screenshot wall ceiling. Webcap already bounds each individual CDP
    # request at ``timeout`` seconds; this covers the full open-tab/navigate/
    # capture/close pipeline (~3 CDP round-trips worst case) with headroom.
    per_screenshot_wall = max(timeout * 4, 30)
    # Attempts per URL. One lost to the browser dying is not counted.
    MAX_ATTEMPTS = 2
    # How many failures with no success in between prompt a health check.
    # Scales with concurrency so one round of bad URLs can't trip it alone.
    FAILURE_CHECK_THRESHOLD = max(5, threads * 2)

    def _new_browser():
        return Browser(timeout=timeout, threads=threads, image_format=image_format, quality=quality)

    browser = _new_browser()
    await browser.start()

    # Bumped on every restart, so a worker can tell "the browser I was using
    # has been replaced" from "the browser is the one I saw".
    generation = 0
    consecutive_failures = 0
    # Held while the browser is being replaced. Workers take it briefly before
    # each attempt, so none of them starts on a browser that is going away.
    browser_lock = asyncio.Lock()

    def _alive(candidate) -> bool:
        # Older webcap builds have no is_alive; treat those as alive and let
        # the health check catch a dead browser instead.
        return bool(getattr(candidate, 'is_alive', True))

    async def _current_browser():
        async with browser_lock:
            return browser, generation

    async def _restart_browser(seen_generation: int, reason: str) -> None:
        nonlocal browser, generation, consecutive_failures
        async with browser_lock:
            if generation != seen_generation:
                # Another worker replaced it while we waited for the lock.
                return
            log.warning('Restarting Chrome (%s)', reason)
            try:
                await browser.stop()
            except Exception:
                pass
            browser = _new_browser()
            await browser.start()
            generation += 1
            consecutive_failures = 0
            # Brief settle so the next request doesn't race the message handler.
            await asyncio.sleep(1)

    async def _sweep_strays(reason: str) -> None:
        """Close pages no screenshot owns. Tabs in use are not touched."""
        log.debug('Sweeping stray tabs (%s)', reason)
        try:
            await browser.force_target_cleanup()
        except Exception as e:
            log.warning('force_target_cleanup failed (%s): %s', reason, e)

    async def _responds(candidate) -> bool:
        """True if Chrome answers a trivial request, i.e. it is not wedged."""
        try:
            response = await asyncio.wait_for(
                candidate.request('Browser.getVersion'), timeout=max(timeout, 5)
            )
        except Exception:
            return False
        return not (isinstance(response, dict) and 'error' in response)

    async def _investigate_failures() -> None:
        """Many failures in a row: decide whether Chrome or the targets are at fault."""
        nonlocal consecutive_failures
        current, seen = await _current_browser()
        # Claim the streak before awaiting, so the other workers don't each
        # start an investigation of their own.
        consecutive_failures = 0
        if _alive(current) and await _responds(current):
            await _sweep_strays('repeated failures')
        else:
            await _restart_browser(seen, 'browser not responding')

    # Shared/exclusive gate for attempts. Normal attempts share it; a URL that
    # was in flight when Chrome died retries with nothing else running, so if
    # it is what kills Chrome it can only take itself down.
    gate = asyncio.Condition()
    gate_state = {'active': 0, 'solo': False, 'solo_waiting': 0}

    async def _enter(solo: bool) -> None:
        async with gate:
            if solo:
                gate_state['solo_waiting'] += 1
                try:
                    await gate.wait_for(
                        lambda: gate_state['active'] == 0 and not gate_state['solo']
                    )
                finally:
                    gate_state['solo_waiting'] -= 1
                gate_state['solo'] = True
            else:
                # Queue behind anyone waiting to go solo, or they'd starve.
                await gate.wait_for(
                    lambda: not gate_state['solo'] and gate_state['solo_waiting'] == 0
                )
            gate_state['active'] += 1

    async def _leave(solo: bool) -> None:
        async with gate:
            gate_state['active'] -= 1
            if solo:
                gate_state['solo'] = False
            gate.notify_all()

    async def _capture(url: str):
        """One URL, with retries. Returns the screenshot, or None."""
        attempt = 0
        # Set once the browser has died under this URL.
        suspect = False
        while attempt < MAX_ATTEMPTS:
            attempt += 1
            solo = suspect
            await _enter(solo)
            try:
                current, seen = await _current_browser()
                if not _alive(current):
                    # A dead browser fails every request instantly; replace
                    # it now rather than burn this attempt on it.
                    await _restart_browser(seen, 'browser no longer running')
                    current, seen = await _current_browser()
                try:
                    return await asyncio.wait_for(
                        current.screenshot(url),
                        timeout=per_screenshot_wall,
                    )
                except asyncio.TimeoutError:
                    log.warning(
                        'Screenshot %s exceeded %ds wall timeout (attempt %d)',
                        url,
                        per_screenshot_wall,
                        attempt,
                    )
                except WebCapError as e:
                    log.error('WebCapError on %s (attempt %d): %s', url, attempt, e)
                except Exception as e:
                    log.error('Error taking screenshot for %s: %s', url, e)
                    log.debug(traceback.format_exc())
                    return None
                browser_lost = generation != seen or not _alive(current)
            finally:
                await _leave(solo)

            if browser_lost:
                if solo:
                    # Nothing else was running, so this URL killed Chrome.
                    log.warning('Giving up on %s: it takes the browser down', url)
                    return None
                # Others were running too, so it may not be this URL's fault.
                # The attempt doesn't count; the retry runs alone to find out.
                suspect = True
                attempt -= 1
        return None

    pending = collections.deque(future_map.items())

    async def _worker(out_file) -> None:
        nonlocal consecutive_failures
        while pending:
            url, scan_tuple = pending.popleft()
            port_id, http_endpoint_data_id, domain_str, path = scan_tuple

            webscreenshot = await _capture(url)

            image_data = None
            if webscreenshot and webscreenshot.status_code != 0:
                try:
                    image_data = base64.b64encode(webscreenshot.blob).decode()
                except ValueError:
                    pass

            if image_data is not None:
                consecutive_failures = 0
                url_entry = {
                    'port_id': port_id,
                    'http_endpoint_data_id': http_endpoint_data_id,
                    'path': path,
                    'domain': domain_str,
                    'url': url,
                    'image_data': image_data,
                    'status_code': webscreenshot.status_code,
                    'title': webscreenshot.title,
                }
                # One write per record, with no await in between, so lines
                # from different workers never interleave.
                out_file.write(json.dumps(url_entry) + '\n')
            else:
                consecutive_failures += 1
                log.warning('Failed to take screenshot for %s', url)

            # webcap saw an event for a session it doesn't know. Usually
            # harmless post-close noise; when it isn't, there is a stray tab.
            if getattr(browser, 'orphaned_session', False):
                # Cleared here so concurrent workers don't all sweep at once.
                browser.orphaned_session = False
                await _sweep_strays('orphan flag')

            if consecutive_failures >= FAILURE_CHECK_THRESHOLD:
                await _investigate_failures()

    workers = []
    try:
        with open(meta_file_path, 'w') as f:
            workers = [asyncio.create_task(_worker(f)) for _ in range(min(threads, len(pending)))]
            if workers:
                await asyncio.gather(*workers)
    finally:
        # Reached with workers still running only if one of them raised (a
        # browser that could not be restarted) or we were cancelled.
        for worker in workers:
            worker.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
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

    # Derive a wall-clock timeout so we never hang indefinitely. Per URL the
    # worst case is the per-screenshot wall ceiling (max(timeout*4, 30)) × 2
    # attempts, plus occasional Chrome restarts. URLs run --threads at a
    # time, but the budget deliberately assumes one at a time: it is a
    # backstop against a hang, not an estimate, and webcap serialises parts
    # of each capture.
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


def _parse_screenshot_line(
    screenshot_meta,
    tool_instance_id,
    screenshot_hash_map,
    path_hash_map,
    domain_name_id_map,
):
    """Convert one parsed Webcap JSON record into its data-model objects.

    The three ``*_map`` dicts carry dedup state across calls; callers control
    their lifetime — whole-file for :func:`parse_webcap_output`, per-batch for
    :func:`iter_webcap_batches` so peak memory stays bounded.
    """
    records = []

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

    records.append(screenshot_obj)
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
        records.append(domain_obj)
        endpoint_domain_id = domain_obj.id

    if web_path_hash in path_hash_map:
        path_obj = path_hash_map[web_path_hash]
    else:
        path_obj = data_model.ListItem()
        path_obj.collection_tool_instance_id = tool_instance_id
        path_obj.web_path = web_path
        path_obj.web_path_hash = web_path_hash
        path_hash_map[web_path_hash] = path_obj

    records.append(path_obj)
    web_path_id = path_obj.id

    http_endpoint_obj = data_model.HttpEndpoint(parent_id=port_id)
    http_endpoint_obj.collection_tool_instance_id = tool_instance_id
    http_endpoint_obj.web_path_id = web_path_id
    records.append(http_endpoint_obj)

    http_endpoint_data_obj = data_model.HttpEndpointData(parent_id=http_endpoint_obj.id)
    http_endpoint_data_obj.collection_tool_instance_id = tool_instance_id
    http_endpoint_data_obj.domain_id = endpoint_domain_id
    http_endpoint_data_obj.status = status_code
    http_endpoint_data_obj.title = title
    http_endpoint_data_obj.screenshot_id = screenshot_id
    if http_endpoint_data_id:
        http_endpoint_data_obj.id = http_endpoint_data_id
    records.append(http_endpoint_data_obj)

    return records


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
            ret_arr.extend(
                _parse_screenshot_line(
                    json.loads(line),
                    tool_instance_id,
                    screenshot_hash_map,
                    path_hash_map,
                    domain_name_id_map,
                )
            )

    return ret_arr


def iter_webcap_batches(meta_file, tool_instance_id, batch_size):
    """Stream a Webcap JSON-lines file as successive batches of records.

    Yields a list of data-model objects for every ``batch_size`` source lines.
    Dedup maps are reset per batch so the resident set never exceeds one
    batch's worth of screenshots (the base64 blobs dominate memory); identical
    screenshots / paths that straddle a batch boundary are re-sent and
    collapsed server-side by their hashes, the same dedup the interrupted-POST
    retry already relies on.
    """
    if not os.path.exists(meta_file):
        return

    with open(meta_file, 'r') as file_fd:
        batch = []
        line_count = 0
        screenshot_hash_map = {}
        path_hash_map = {}
        domain_name_id_map = {}
        for line in file_fd:
            if not line.strip():
                continue
            batch.extend(
                _parse_screenshot_line(
                    json.loads(line),
                    tool_instance_id,
                    screenshot_hash_map,
                    path_hash_map,
                    domain_name_id_map,
                )
            )
            line_count += 1
            if line_count >= batch_size:
                yield batch
                batch = []
                line_count = 0
                screenshot_hash_map = {}
                path_hash_map = {}
                domain_name_id_map = {}

        if batch:
            yield batch
