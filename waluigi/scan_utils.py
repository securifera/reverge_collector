from functools import wraps
import math
import os
import subprocess
import re
import threading
import time
import traceback
import netaddr
import logging

from json import JSONDecoder, JSONDecodeError
from threading import Thread
from queue import Queue
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, Future
from urllib.parse import urlparse

from waluigi.data_model import ToolExecutor

NOT_WHITESPACE = re.compile(r'\S')
logger = logging.getLogger(__name__)


class ThreadExecutorWrapper():

    def __init__(self, max_workers=10):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.results = []
        self.exceptions = []
        self.futures_map = {}
        self.lock = threading.Lock()
        self.task_counter = 0

    def _internal_callback(self, future: Future):

        with self.lock:
            task_id = self.futures_map.pop(future, None)

        if task_id is None:
            logger.warning("Future not found in the map.")
            return

        try:
            result = future.result()
            with self.lock:
                self.results.append((task_id, result))
            # logger.debug(f"Task {task_id} completed with result: {result}")
            logger.debug(f"Task {task_id} completed")

        except Exception as e:
            tb = traceback.format_exc()
            with self.lock:
                self.exceptions.append((task_id, e, tb))
            logger.debug(f"Task {task_id} raised an exception: {e}")
            logger.debug(f"Traceback:\n{tb}")

    def submit(self, fn, *args, **kwargs):

        with self.lock:
            task_id = self.task_counter
            self.task_counter += 1

        future = self.executor.submit(fn, *args, **kwargs)
        with self.lock:
            self.futures_map[future] = task_id
        future.add_done_callback(self._internal_callback)

        return future

    def shutdown(self, wait=True):
        """
        Shuts down the executor, optionally waiting for currently executing tasks to finish.

        :param wait: If True, wait for all pending futures to finish.
        """
        self.executor.shutdown(wait=wait)
        logger.debug("Executor has been shut down.")


class ProcessStreamReader(Thread):

    class StreamType(Enum):
        STDOUT = 1
        STDERR = 2

    def __init__(self, pipe_type, pipe_stream, print_output=False, store_output=False):
        Thread.__init__(self)
        self.pipe_type = pipe_type
        self.pipe_stream = pipe_stream
        self.output_queue = Queue()
        self._daemon = True
        self.daemon = True
        self.print_output = print_output
        self.store_output = store_output

    def queue(self, data):
        self.output_queue.put(data)

    def run(self):

        pipe = self.pipe_stream
        try:
            with pipe:
                for line in iter(pipe.readline, b''):
                    if self.print_output:
                        print(line.decode())

                    if self.store_output:
                        self.queue(line)
        except Exception as e:
            print("[-] Exception: " + str(e))
            pass
        finally:
            self.queue(None)

    def get_output(self):

        output_str = ''
        try:
            output_bytes = b''
            for line in iter(self.output_queue.get, None):
                output_bytes += line

            output_str = output_bytes.decode()
        except Exception as e:
            logger.error("Error getting process output: %s" % str(e))

        return output_str


def execution_time(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        start_time = int(time.time())
        result = f(*args, **kwargs)
        end_time = int(time.time())
        logger.debug(
            f"Execution time of '{f.__name__}': {end_time-start_time} seconds")
        return result

    return wrapper


def get_url_port(url):

    port_int = None
    try:
        u = urlparse(url)
        port_int = 80
        if u.port is not None:
            port_int = u.port
        else:
            if u.scheme == 'https':
                port_int = 443

        return port_int
    except Exception as e:
        logger.error("Invalid URL")
        return port_int


def construct_url(target_str, port, secure, query_str=None):

    if target_str is None or port is None or secure is None:
        return None

    port_str = str(port).strip()
    add_port_flag = True
    url = "http"
    if secure:
        url += "s"
        if port_str == '443':
            add_port_flag = False
    elif port_str == '80':
        add_port_flag = False

    url += "://" + target_str
    if add_port_flag:
        url += ":" + port_str

    if query_str:
        url += query_str

    return url


def get_ports(byte_array):
    # Get byte
    port_list = []
    if byte_array:
        for i in range(0, len(byte_array)):
            current_byte = byte_array[i]
            for j in range(8):
                mask = 1 << j
                if current_byte & mask:
                    port_list.append(str(j + (i*8)))
    return port_list


def set_bit(num, byte_array):
    # Get byte
    byte_num = math.floor(num / 8)
    bit_pos = num % 8

    if byte_num < len(byte_array):
        current_byte = byte_array[byte_num]
        byte_array[byte_num] = current_byte | (1 << bit_pos)


def get_port_byte_array(port_list):

    port_map_bytes = bytearray(8192)
    if len(port_list) > 0:

        # Split on comma or space
        split_delim = None
        if "," in port_list:
            split_delim = ","
        elif " " in port_list:
            split_delim = " "

        port_arr = [port_list]
        if split_delim:
            port_arr = port_list.split(split_delim)

        # Iterate over list
        for port_inst in port_arr:
            port_range_arr = port_inst.split("-")
            if len(port_range_arr) == 1:
                set_bit(int(port_range_arr[0]), port_map_bytes)
            else:
                start = int(port_range_arr[0])
                end = int(port_range_arr[1])
                for port in range(start, end + 1):
                    set_bit(int(port), port_map_bytes)

    return port_map_bytes


def check_domain(domain_str):

    # If it's a wildcard
    if "*." in domain_str:
        return None

    # If it's an IP skip it
    try:
        ip_addr_check = int(netaddr.IPAddress(domain_str))
        return None
    except:
        pass

    return domain_str


def init_tool_folder(tool_name, desc, scan_id):

    # Create directory if it doesn't exist
    cwd = os.getcwd()
    dir_path = cwd + os.path.sep + scan_id + \
        os.path.sep + "%s-%s" % (tool_name, desc)
    if not os.path.isdir(dir_path):
        os.makedirs(dir_path)
        os.chmod(dir_path, 0o777)

    return dir_path


def process_wrapper(cmd_args, use_shell=False, my_env=None, print_output=False, store_output=False, pid_callback=None):

    logger.debug("Executing '%s'" % str(cmd_args))
    p = subprocess.Popen(cmd_args, shell=use_shell, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=my_env)

    # If a callback is provided, call it with the process ID
    if pid_callback:
        scan_proc_inst = ToolExecutor(proc_pids=set([p.pid]))
        pid_callback(scan_proc_inst)

    stdout_reader = ProcessStreamReader(
        ProcessStreamReader.StreamType.STDOUT, p.stdout, print_output, store_output)
    stderr_reader = ProcessStreamReader(
        ProcessStreamReader.StreamType.STDERR, p.stderr, print_output, store_output)

    p.stdin.close()

    stdout_reader.start()
    stderr_reader.start()

    exit_code = p.wait()

    ret_data = {"exit_code": exit_code, "stdout": stdout_reader.get_output(
    ), "stderr": stderr_reader.get_output()}
    return ret_data


def parse_json_blob_file(output_file):

    obj_arr = []

    if os.path.exists(output_file):

        # Open the file and read all the data
        with open(output_file, 'r') as file_fd:
            data = file_fd.read()

        if len(data) > 0:

            decoder = JSONDecoder()
            pos = 0

            while True:

                # Find the next character that's not a whitespace
                match = NOT_WHITESPACE.search(data, pos)
                if not match:
                    break
                pos = match.start()

                try:
                    obj, pos = decoder.raw_decode(data, pos)
                except JSONDecodeError:
                    print("[-] JSON decoding error")
                    break

                # Add object
                obj_arr.append(obj)

    return obj_arr


# Create thread executor
executor = ThreadExecutorWrapper()
