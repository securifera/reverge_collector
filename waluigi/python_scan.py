"""
Python Active Script Execution Module for the Waluigi Framework.

This module enables active execution of Python scripts against discovered network ports
within the Waluigi framework. It is designed to automate custom Python-based scanning,
analysis, or exploitation tasks, integrating results into the Waluigi data model for
further processing and reporting.

Features:
    - Executes user-supplied Python scripts against network ports
    - Integrates with Luigi for workflow orchestration
    - Structured output for downstream import and analysis
    - Supports custom arguments and port mapping
    - Error handling and logging for scan execution

Classes:
    Python: Main tool class for Python script execution
    PythonScan: Luigi task for running Python scripts against discovered ports
    ImportPythonOutput: Luigi task for importing and processing Python scan results

Example:
    Basic usage through the Waluigi framework::
        python_tool = Python()
        success = python_tool.scan_func(scan_input_obj)
        imported = python_tool.import_func(scan_input_obj)

Note:
    This module requires valid Python scripts and appropriate arguments to be supplied
    via the Waluigi framework. Ensure that all dependencies are installed and accessible
    in the execution environment.

.. moduleauthor:: Waluigi Framework Team
.. version:: 1.0.0
"""

from functools import partial
import json
import os
from typing import Dict, Any, List, Set, Optional
import logging

from waluigi import scan_utils
from waluigi import data_model
from waluigi.proc_utils import process_wrapper
from waluigi.tool_runner import (
    import_already_done as _import_already_done,
    import_results as _import_results,
)


class Python(data_model.WaluigiTool):
    """
    Main tool class for Python script execution within the Waluigi framework.

    Attributes:
        name (str): Tool name identifier ('python').
        description (str): Description of the tool's purpose.
        project_url (str): Reference URL for Python.
        collector_type (str): Collector type (active).
        scan_order (int): Execution order in scan pipeline.
        args (str): Custom arguments for script execution.
        input_records (list): Expected input record types.
        output_records (list): Output record types produced.
        scan_func (callable): Function to execute scan.
        import_func (callable): Function to import scan results.
    """

    def __init__(self) -> None:

        super().__init__()
        self.name: str = 'python'
        self.description: str = 'Python is a versatile programming language that enables rapid development and automation.'
        self.project_url: str = 'https://www.python.org/'
        self.tags = ['code-exec']
        self.collector_type: str = data_model.CollectorType.ACTIVE.value
        self.scan_order: int = 7
        self.args: str = ""
        self.input_records = [data_model.ServerRecordType.PORT]
        self.output_records = [
            data_model.ServerRecordType.COLLECTION_MODULE,
            data_model.ServerRecordType.COLLECTION_MODULE_OUTPUT,
        ]
        self.scan_func = Python.python_scan_func
        self.import_func = Python.python_import

    @staticmethod
    @staticmethod
    def python_scan_func(scan_input: data_model.ScheduledScan) -> bool:
        try:
            execute_scan(scan_input)
            return True
        except Exception as e:
            logging.getLogger(__name__).error(
                "Python scan failed: %s", e, exc_info=True)
            raise

    @staticmethod
    def python_import(scan_input: data_model.ScheduledScan) -> bool:
        try:
            output_path = get_output_path(scan_input)
            if not os.path.exists(output_path):
                return True
            if _import_already_done(scan_input, output_path):
                return True
            scheduled_scan_obj = scan_input
            ret_arr = parse_python_scan_output(
                output_path,
                scheduled_scan_obj.current_tool_instance_id,
                scheduled_scan_obj.current_tool.id,
                scheduled_scan_obj.scan_data.host_port_obj_map,
            )
            _import_results(scan_input, ret_arr, output_path)
            return True
        except Exception as e:
            logging.getLogger(__name__).error(
                "Python import failed: %s", e, exc_info=True)
            raise


def get_output_path(scan_input: data_model.ScheduledScan) -> str:
    scan_id: str = scan_input.id
    tool_name: str = scan_input.current_tool.name
    dir_path: str = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)
    return f"{dir_path}{os.path.sep}{tool_name}_outputs_{scan_id}"


def execute_scan(scan_input: data_model.ScheduledScan) -> None:
    output_file_path = get_output_path(scan_input)
    if os.path.exists(output_file_path):
        return

    scheduled_scan_obj = scan_input
    scope_obj = scheduled_scan_obj.scan_data

    target_map: Dict[str, Dict[str, Any]] = scope_obj.host_port_obj_map
    custom_args: Optional[List[str]] = None

    if scheduled_scan_obj.current_tool.args:
        custom_args = scheduled_scan_obj.current_tool.args
    else:
        raise RuntimeError("Custom arguments are required for the scan.")

    scan_results = ''
    if len(target_map) > 0:

        # Build command arguments
        command: List[str] = [
            "python3"
        ]

        # Execute scan with process tracking
        callback_with_tool_id = partial(
            scheduled_scan_obj.register_tool_executor, scheduled_scan_obj.current_tool_instance_id)

        future_inst = scan_utils.executor.submit(
            process_wrapper, cmd_args=command, stdin_data=custom_args, pid_callback=callback_with_tool_id, store_output=True)

        # Wait for scan completion
        ret_dict = future_inst.result()
        if ret_dict:
            if 'exit_code' in ret_dict:
                exit_code = ret_dict['exit_code']
                if exit_code != 0:
                    err_msg = ''
                    if 'stderr' in ret_dict and ret_dict['stderr']:
                        err_msg = ret_dict['stderr']
                    logging.getLogger(__name__).error(
                        "Python scan for scan ID %s exited with code %d: %s" % (scheduled_scan_obj.id, exit_code, err_msg))
                    raise RuntimeError("Python scan for scan ID %s exited with code %d: %s" % (
                        scheduled_scan_obj.id, exit_code, err_msg))
            if 'stdout' in ret_dict and ret_dict['stdout']:
                scan_results = ret_dict['stdout']
    else:
        raise RuntimeError(
            "No ports found for Python scan. Skipping scan execution.")

    # Write output file
    with open(output_file_path, 'w') as file_fd:
        file_fd.write(scan_results)


def parse_python_scan_output(output_file, tool_instance_id, tool_id, target_map=None):
    """Parse a Python scan output file and return data-model objects."""
    with open(output_file, 'r') as file_fd:
        data = file_fd.read()

    ret_arr: List[Any] = []
    if len(data) > 0:

        # Add collection module for non-module scans
        module_obj = data_model.CollectionModule(
            parent_id=tool_id)
        module_obj.collection_tool_instance_id = tool_instance_id
        module_obj.name = "python-script"
        module_obj.args = ''
        ret_arr.append(module_obj)
        module_id = module_obj.id

        if target_map is not None:
            for target_key in target_map:
                target_obj_dict = target_map[target_key]
                port_obj = target_obj_dict['port_obj']
                port_id: int = port_obj.id

                # Add module output for all scan results
                if module_id:
                    module_output_obj = data_model.CollectionModuleOutput(
                        parent_id=module_id)
                    module_output_obj.collection_tool_instance_id = tool_instance_id
                    module_output_obj.output = data
                    module_output_obj.port_id = port_id
                    ret_arr.append(module_output_obj)

    return ret_arr

