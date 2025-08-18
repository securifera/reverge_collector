import os
import luigi
import logging
import json

from typing import Dict, Any, List, Set, Optional
from luigi.util import inherits
from waluigi import scan_utils
from waluigi import data_model
from iis_shortname_scan import Scanner


class IISShortnameScanner(data_model.WaluigiTool):

    def __init__(self) -> None:

        self.name: str = 'iis_shortname_scanner'
        self.description: str = 'IIS Shortname Scanner is a tool for discovering short filenames on IIS servers.'
        self.project_url: str = 'https://github.com/lijiejie/IIS_shortname_Scanner'
        self.collector_type: str = data_model.CollectorType.ACTIVE.value
        self.scan_order: int = 8
        self.args: str = ""
        self.input_records = [data_model.ServerRecordType.PORT]
        self.output_records = [
            data_model.ServerRecordType.COLLECTION_MODULE,
            data_model.ServerRecordType.COLLECTION_MODULE_OUTPUT,
        ]
        self.scan_func = IISShortnameScanner.iis_short_scan_func
        self.import_func = IISShortnameScanner.iis_short_scan_import

    @staticmethod
    def iis_short_scan_func(scan_input: data_model.ScheduledScan) -> bool:
        """
        Executes the IISShortnameScanner Luigi task for active script execution.

        Args:
            scan_input (ScheduledScan): Scheduled scan object containing scan parameters.
        Returns:
            bool: True if scan succeeded, False otherwise.
        """

        luigi_run_result = luigi.build([IISShortScan(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True

    @staticmethod
    def iis_short_scan_import(scan_input: data_model.ScheduledScan) -> bool:
        """
        Executes the ImportIISShortnameScannerOutput Luigi task to import scan results.

        Args:
            scan_input (ScheduledScan): Scheduled scan object containing scan parameters.
        Returns:
            bool: True if import succeeded, False otherwise.
        """

        luigi_run_result = luigi.build([ImportIISShortScannerOutput(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


def iis_short_scan_wrap(target) -> Dict[str, Any]:

    try:
        with Scanner(target, silent=True) as scanner:
            if not scanner.is_vulnerable():
                return {
                    'target': target,
                    'vulnerable': False,
                    'files': [],
                    'dirs': []
                }

            scanner.run()
            return {
                'target': target,
                'vulnerable': True,
                'files': scanner.files.copy(),
                'dirs': scanner.dirs.copy()
            }

    except Exception as e:
        logging.getLogger(__name__).warning(
            f"Error scanning target {target}: {e}")
        return {
            'target': target,
            'vulnerable': False,
            'error': str(e),
            'files': [],
            'dirs': []
        }


class IISShortScan(luigi.Task):
    """
    Luigi task for executing IISShortScan scan jobs against discovered network ports.

    This task prepares the environment, constructs command arguments, and runs the
    specified IISShortScan job using process tracking. Results are written to a structured
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
        Executes the IISShortScan job against all discovered ports.

        Prepares the environment, builds command arguments, and runs the job.
        Handles errors and writes results to the output file.

        Raises:
            RuntimeError: If no ports are found or scan execution fails.
        """

        scheduled_scan_obj = self.scan_input
        scope_obj = scheduled_scan_obj.scan_data

        # Get output file path
        output_file_path: str = self.output().path

        target_map: Dict[str, Dict[str, Any]] = scope_obj.host_port_obj_map
        port_id_results_map: Dict[int, List[Dict[str, Any]]] = {}
        if len(target_map) > 0:

            futures: List[Any] = []
            for target_key in target_map:

                target_obj_dict = target_map[target_key]
                port_obj = target_obj_dict['port_obj']
                port_id: int = port_obj.id

                # Check if we already added this port
                if port_id in port_id_results_map:
                    continue

                # Get urls
                url_list = port_obj.get_urls(scope_obj)
                port_id_results_map[port_id] = []
                for url in url_list:
                    future_inst = scan_utils.executor.submit(
                        iis_short_scan_wrap, target=url)
                    futures.append((future_inst, port_id))

            # Wait for scan completion
            for future_inst, port_id in futures:
                scan_result = future_inst.result()
                if scan_result:
                    port_id_results_map[port_id].append(scan_result)

        else:
            raise RuntimeError(
                "No ports found for Python scan. Skipping scan execution.")

        # Write output file
        with open(output_file_path, 'w') as file_fd:
            file_fd.write(json.dumps(port_id_results_map))


@inherits(IISShortScan)
class ImportIISShortScannerOutput(data_model.ImportToolXOutput):
    """
    Luigi task for importing and processing IIS Shortname Scanner results.

    This task reads the output file produced by IISShortScan, parses results,
    and integrates them into the Waluigi data model as CollectionModule and
    CollectionModuleOutput records.

    Methods:
        requires(): Specifies dependency on IISShortScan task.
        run(): Imports results and updates the data model.
    """

    def requires(self) -> IISShortScan:
        """
        Specifies that ImportIISShortScannerOutput depends on completion of IISShortScan.

        Returns:
            IISShortScan: The required IISShortScan task instance.
        """

        return IISShortScan(scan_input=self.scan_input)

    def run(self) -> None:
        """
        Imports and processes IISShortScan scan results from the output file.

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

            # Add collection module for non-module scans
            module_obj = data_model.CollectionModule(
                parent_id=tool_id)
            module_obj.collection_tool_instance_id = tool_instance_id
            module_obj.name = "iis-shortname-scan"
            module_obj.args = ''
            ret_arr.append(module_obj)
            module_id = module_obj.id

            result_map = json.loads(data)
            for port_id in result_map.keys():

                result_entry_list = result_map[port_id]

                # Add module output for all scan results
                if module_id:
                    module_output_obj = data_model.CollectionModuleOutput(
                        parent_id=module_id)
                    module_output_obj.collection_tool_instance_id = tool_instance_id
                    module_output_obj.output = json.dumps(result_entry_list)
                    module_output_obj.port_id = port_id
                    ret_arr.append(module_output_obj)

        # Import, Update, & Save all collected results
        self.import_results(scheduled_scan_obj, ret_arr)
