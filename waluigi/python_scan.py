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
import luigi
import logging

from luigi.util import inherits
from waluigi import scan_utils
from waluigi import data_model
from waluigi.proc_utils import process_wrapper


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

        self.name: str = 'python'
        self.description: str = 'Python is a versatile programming language that enables rapid development and automation.'
        self.project_url: str = 'https://www.python.org/'
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
    def python_scan_func(scan_input: data_model.ScheduledScan) -> bool:
        """
        Executes the PythonScan Luigi task for active script execution.

        Args:
            scan_input (ScheduledScan): Scheduled scan object containing scan parameters.
        Returns:
            bool: True if scan succeeded, False otherwise.
        """

        luigi_run_result = luigi.build([PythonScan(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True

    @staticmethod
    def python_import(scan_input: data_model.ScheduledScan) -> bool:
        """
        Executes the ImportPythonOutput Luigi task to import scan results.

        Args:
            scan_input (ScheduledScan): Scheduled scan object containing scan parameters.
        Returns:
            bool: True if import succeeded, False otherwise.
        """

        luigi_run_result = luigi.build([ImportPythonOutput(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


class PythonScan(luigi.Task):
    """
    Luigi task for executing Python scripts against discovered network ports.

    This task prepares the environment, constructs command arguments, and runs the
    specified Python script using process tracking. Results are written to a structured
    output file for downstream import.

    Attributes:
        scan_input (luigi.Parameter): Scheduled scan object containing scan parameters.
    """
    scan_input: luigi.Parameter = luigi.Parameter()

    def output(self) -> luigi.LocalTarget:
        """
        Defines the output target for the scan results.

        Returns:
            luigi.LocalTarget: Target file for scan output.
        """

        scheduled_scan_obj = self.scan_input
        scan_id: str = scheduled_scan_obj.id

        #  Init directory
        tool_name: str = scheduled_scan_obj.current_tool.name
        dir_path: str = scan_utils.init_tool_folder(
            tool_name, 'outputs', scan_id)

        python_outputs_file: str = f"{dir_path}{os.path.sep}{tool_name}_outputs_{scan_id}"
        return luigi.LocalTarget(python_outputs_file)

    def run(self) -> None:
        """
        Executes the Python script against all discovered ports.

        Prepares the environment, builds command arguments, and runs the script.
        Handles errors and writes results to the output file.

        Raises:
            RuntimeError: If no ports are found or scan execution fails.
        """

        scheduled_scan_obj = self.scan_input
        scope_obj = scheduled_scan_obj.scan_data

        # Get output file path
        output_file_path: str = self.output().path

        target_map: Dict[str, Dict[str, Any]] = scope_obj.host_port_obj_map
        custom_args: Optional[List[str]] = None

        if scheduled_scan_obj.current_tool.args:
            custom_args = scheduled_scan_obj.current_tool.args
        else:
            raise RuntimeError("Custom arguments are required for the scan.")

        # Write to nuclei input file if endpoints exist
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


@inherits(PythonScan)
class ImportPythonOutput(data_model.ImportToolXOutput):
    """
    Luigi task for importing and processing Python scan results.

    This task reads the output file produced by PythonScan, parses results,
    and integrates them into the Waluigi data model as CollectionModule and
    CollectionModuleOutput records.

    Methods:
        requires(): Specifies dependency on PythonScan task.
        run(): Imports results and updates the data model.
    """

    def requires(self) -> PythonScan:
        """
        Specifies that ImportPythonOutput depends on completion of PythonScan.

        Returns:
            PythonScan: The required PythonScan task instance.
        """

        return PythonScan(scan_input=self.scan_input)

    def run(self) -> None:
        """
        Imports and processes Python scan results from the output file.

        Reads scan output, maps results to discovered ports, and creates
        CollectionModule and CollectionModuleOutput records for each port.
        Updates the Waluigi data model with imported results.
        """

        scheduled_scan_obj = self.scan_input
        tool_instance_id: int = scheduled_scan_obj.current_tool_instance_id
        scope_obj = scheduled_scan_obj.scan_data
        target_map: Dict[str, Dict[str, Any]] = scope_obj.host_port_obj_map

        # Import the ports to the manager
        tool_id: int = scheduled_scan_obj.current_tool.id

        python_output_file: str = self.input().path
        with open(python_output_file, 'r') as file_fd:
            data: str = file_fd.read()

        ret_arr: List[Any] = []
        if len(data) > 0:

            for target_key in target_map:
                target_obj_dict = target_map[target_key]
                port_obj = target_obj_dict['port_obj']
                port_id: int = port_obj.id

                # Add collection module for non-module scans
                module_obj = data_model.CollectionModule(
                    parent_id=tool_id)
                module_obj.collection_tool_instance_id = tool_instance_id
                module_obj.name = "python-script"
                module_obj.args = ''
                ret_arr.append(module_obj)
                module_id = module_obj.id

                # Add module output for all scan results
                if module_id:
                    module_output_obj = data_model.CollectionModuleOutput(
                        parent_id=module_id)
                    module_output_obj.collection_tool_instance_id = tool_instance_id
                    module_output_obj.output = data
                    module_output_obj.port_id = port_id
                    ret_arr.append(module_output_obj)

        # Import, Update, & Save all collected results
        self.import_results(scheduled_scan_obj, ret_arr)
