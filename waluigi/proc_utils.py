"""
Process Utilities Module.

This module provides process execution and monitoring utilities for the Waluigi framework.
It includes subprocess wrappers, stream capture, and process management functionality.
"""

import os
import subprocess
import logging
from threading import Thread
from queue import Queue
from enum import Enum
from typing import Dict, List, Any, Optional, Callable, Set

from waluigi.data_model import ToolExecutor


class ProcessStreamReader(Thread):
    """
    Thread-based stream reader for capturing process output.

    This class provides asynchronous reading of process streams (stdout/stderr)
    using a separate thread to prevent blocking operations. It captures output
    line by line and makes it available through a queue-based interface.
    """

    class StreamType(Enum):
        """Enumeration for identifying stream types."""
        STDOUT = 1
        STDERR = 2

    def __init__(self, pipe_type: 'ProcessStreamReader.StreamType',
                 pipe_stream, print_output: bool = False, store_output: bool = True) -> None:
        """
        Initialize the stream reader with specified parameters.

        Args:
            pipe_type (StreamType): The type of stream (STDOUT or STDERR).
            pipe_stream: The stream object to read from (typically from subprocess).
            print_output (bool): Whether to print output lines in real-time.
                Defaults to False for silent operation.
            store_output (bool): Whether to store output in queue.
                Defaults to True.
        """
        Thread.__init__(self)
        self.pipe_type = pipe_type
        self.pipe_stream = pipe_stream
        self.output_queue: Queue = Queue()
        self._daemon = True
        self.daemon = True
        self.print_output = print_output
        self.store_output = store_output

    def queue(self, data: Optional[bytes]) -> None:
        """
        Add data to the output queue.

        Args:
            data (Optional[bytes]): Data to add to queue, or None to signal completion.
        """
        self.output_queue.put(data)

    def run(self) -> None:
        """
        Main thread execution method for reading the stream.
        """
        pipe = self.pipe_stream
        try:
            while True:
                line = pipe.readline()
                if not line:
                    break
                if self.print_output:
                    logging.getLogger(__name__).debug(line.decode())
                if self.store_output:
                    self.queue(line)
        except Exception as e:
            logging.getLogger(__name__).error("Exception: " + str(e))
        finally:
            self.queue(None)

    def get_output(self) -> str:
        """
        Retrieve all collected output as a decoded string.
        """
        output_str = ''
        try:
            output_bytes = b''
            for line in iter(self.output_queue.get, None):
                output_bytes += line
            output_str = output_bytes.decode()
        except Exception as e:
            logging.getLogger(__name__).error(
                f"Error getting process output: {str(e)}")
        return output_str


def process_wrapper(cmd_args: List[str], use_shell: bool = False,
                    my_env: Optional[Dict[str, str]] = None,
                    print_output: bool = False, store_output: bool = False,
                    pid_callback: Optional[Callable] = None) -> Dict[str, Any]:
    """
    Execute a process with comprehensive monitoring and output capture.

    This function provides a robust wrapper around subprocess execution with
    support for output capture, real-time monitoring, process ID tracking,
    and callback functionality for integration with the scanning framework.

    Args:
        cmd_args (List[str]): Command and arguments to execute.
        use_shell (bool): Whether to execute through shell. Defaults to False.
        my_env (Optional[Dict[str, str]]): Environment variables for the process.
        print_output (bool): Whether to print output in real-time. Defaults to False.
        store_output (bool): Whether to capture and return output. Defaults to False.
        pid_callback (Optional[Callable]): Callback function to receive process ID.

    Returns:
        Dict[str, Any]: Dictionary containing execution results with keys:
            - 'exit_code' (int): Process exit code
            - 'stdout' (str): Standard output (if store_output=True)
            - 'stderr' (str): Standard error (if store_output=True)
    """
    logging.getLogger(__name__).debug("Executing '%s'" % str(cmd_args))

    # Configure output capture based on parameters
    pipe_type = subprocess.DEVNULL
    if store_output:
        pipe_type = subprocess.PIPE

    # Start the process
    p = subprocess.Popen(cmd_args, shell=use_shell, stdin=subprocess.PIPE,
                         stdout=pipe_type, stderr=subprocess.PIPE, env=my_env)

    # Provide process ID to callback if specified
    if pid_callback:
        scan_proc_inst = ToolExecutor(proc_pids=set([p.pid]))
        pid_callback(scan_proc_inst)

    p.stdin.close()

    # Set up stream readers for output capture
    if store_output:
        stdout_reader = ProcessStreamReader(
            ProcessStreamReader.StreamType.STDOUT, p.stdout, print_output, store_output)
        stdout_reader.start()

    stderr_reader = ProcessStreamReader(
        ProcessStreamReader.StreamType.STDERR, p.stderr, print_output, True)
    stderr_reader.start()

    # Wait for process completion
    exit_code = p.wait()

    # Prepare return data
    ret_data = {"exit_code": exit_code}

    # Collect output if requested
    if store_output:
        ret_data["stdout"] = stdout_reader.get_output()

    ret_data["stderr"] = stderr_reader.get_output()
    return ret_data
