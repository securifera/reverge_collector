"""
SQLMap SQL Injection Scanner Module.

This module provides SQL injection scanning capabilities using SQLMap,
a powerful open-source penetration testing tool that automates the process
of detecting and exploiting SQL injection flaws and taking over database servers.
It integrates with the Waluigi framework to perform automated SQL injection
testing against web targets.

The module supports:
    - Automated SQL injection detection and exploitation
    - Multi-target concurrent scanning
    - URL-based target collection (same pattern as NucleiScan/FeroxScan)
    - Vulnerability reporting and cataloging
    - Integration with Luigi workflow management

Classes:
    Sqlmap: Main tool class implementing the scanner interface
    SqlmapScan: Luigi task for executing SQLMap scans
    ImportSqlmapOutput: Luigi task for importing and processing scan results

Functions:
    parse_sqlmap_output: Parses SQLMap output files and returns data_model Record objects

Global Variables:
    url_set: Thread-safe set tracking queued URLs to prevent duplicates
    SQLMAP_PATH: File system path to the SQLMap Python script

Example:
    Basic usage through the Waluigi framework::

        # Initialize the tool
        sqlmap = Sqlmap()

        # Execute scan
        success = sqlmap.scan_func(scan_input_obj)

        # Import results
        imported = sqlmap.import_func(scan_input_obj)

Note:
    This module requires SQLMap to be installed at /opt/sqlmap/sqlmap.py.
    The tool performs active scanning and should be used responsibly with proper
    authorization on target systems.
"""

from functools import partial
import json
import os
from typing import Dict, Any, Set, Optional, List
import luigi
import logging
import random

from luigi.util import inherits
from waluigi import scan_utils
from waluigi import data_model
from waluigi.proc_utils import process_wrapper

# Global URL tracking set to prevent duplicate scanning
url_set: Set[str] = set()

# Path to the SQLMap Python script
SQLMAP_PATH = "/opt/sqlmap/sqlmap.py"


class Sqlmap(data_model.WaluigiTool):
    """
    SQLMap SQL injection scanner integration for the Waluigi framework.

    This class provides integration with SQLMap, a powerful open-source
    penetration testing tool that automates the detection and exploitation
    of SQL injection flaws. It implements the WaluigiTool interface to provide
    SQL injection testing capabilities within the reconnaissance workflow.

    Attributes:
        name (str): The tool identifier ('sqlmap')
        description (str): Human-readable description of the tool's purpose
        project_url (str): URL to the SQLMap project repository
        collector_type (int): Identifies this as an active scanning tool
        scan_order (int): Execution priority within the scanning workflow (12)
        args (str): Default command-line arguments for automated scanning
        scan_func (callable): Static method for executing scan operations
        import_func (callable): Static method for importing scan results

    Methods:
        sqlmap_scan_func: Executes SQL injection scanning operations
        sqlmap_import: Imports and processes scan results

    Example:
        >>> tool = Sqlmap()
        >>> print(tool.name)
        sqlmap

        >>> # Execute scan through the framework
        >>> success = tool.scan_func(scan_input_obj)
        >>> if success:
        ...     imported = tool.import_func(scan_input_obj)

    Note:
        Default arguments use --batch for non-interactive mode with level 1
        and risk 1 for safe, automated scanning behaviour.
        The scan_order of 12 positions this tool after FeroxBuster (10) so
        that discovered endpoints can also be tested for SQL injection.
    """

    def __init__(self) -> None:
        """
        Initialize the SQLMap tool with default configuration.

        Sets up the tool with safe default parameters for SQL injection scanning,
        including non-interactive batch mode and conservative testing levels to
        ensure effective and responsible scanning behaviour.
        """
        super().__init__()
        self.name = 'sqlmap'
        self.description = (
            'SQLMap is an open source penetration testing tool that automates '
            'the process of detecting and exploiting SQL injection flaws and '
            'taking over database servers'
        )
        self.project_url = "https://sqlmap.org/"
        self.tags = ['vuln-scan']
        self.collector_type = data_model.CollectorType.ACTIVE.value
        self.scan_order = 12
        self.args = "--batch --level=1 --risk=1 --crawl=2"
        self.scan_func = Sqlmap.sqlmap_scan_func
        self.import_func = Sqlmap.sqlmap_import
        self.input_records = [
            data_model.ServerRecordType.PORT,
            data_model.ServerRecordType.HTTP_ENDPOINT_DATA,
        ]
        self.output_records = [
            data_model.ServerRecordType.VULNERABILITY,
        ]

    @staticmethod
    def sqlmap_scan_func(scan_input: Any) -> bool:
        """
        Execute SQLMap SQL injection scanning operations.

        This static method serves as the entry point for executing SQLMap scans
        within the Waluigi framework. It builds and runs the SqlmapScan Luigi task
        with the provided scan input configuration.

        Args:
            scan_input (Any): The scan input object containing target information,
                            tool configuration, and execution parameters

        Returns:
            bool: True if the scan completed successfully, False otherwise

        Example:
            >>> scan_obj = create_scan_input(...)
            >>> success = Sqlmap.sqlmap_scan_func(scan_obj)
            >>> print(f"Scan successful: {success}")
        """
        luigi_run_result = luigi.build(
            [SqlmapScan(scan_input=scan_input)],
            local_scheduler=True,
            detailed_summary=True,
        )
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True

    @staticmethod
    def sqlmap_import(scan_input: Any) -> bool:
        """
        Import and process SQLMap scan results.

        This static method handles the import phase of the scanning workflow,
        processing SQLMap output files and importing discovered SQL injection
        vulnerabilities into the database structure.

        Args:
            scan_input (Any): The scan input object containing configuration
                            and metadata for the import operation

        Returns:
            bool: True if the import completed successfully, False otherwise

        Example:
            >>> imported = Sqlmap.sqlmap_import(scan_obj)
            >>> print(f"Import successful: {imported}")
        """
        luigi_run_result = luigi.build(
            [ImportSqlmapOutput(scan_input=scan_input)],
            local_scheduler=True,
            detailed_summary=True,
        )
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


class SqlmapScan(luigi.Task):
    """
    Luigi task for executing SQLMap SQL injection scanning operations.

    This task orchestrates the execution of SQLMap scans against web targets,
    managing input parameters, output file generation, and execution flow within
    the Luigi workflow framework.  It uses the same URL extraction pattern as
    NucleiScan and FeroxScan, leveraging get_urls() to collect all reachable
    HTTP endpoints as targets.

    Attributes:
        scan_input (luigi.Parameter): The scan input object containing target
                                     information and configuration parameters

    Methods:
        output: Defines the output file target for the scan results
        run: Executes the actual SQLMap scanning operation

    Example:
        >>> task = SqlmapScan(scan_input=scan_obj)
        >>> luigi.build([task])

    Note:
        Unlike FeroxScan, all URLs (including those with non-root paths) are
        included as targets, since SQL injection testing is relevant for any
        URL that may accept parameters.
    """

    scan_input = luigi.Parameter()

    def output(self) -> luigi.LocalTarget:
        """
        Define the output file target for SQLMap scan results.

        Returns:
            luigi.LocalTarget: A Luigi target representing the output file where
                             the URL-to-output-file mapping will be stored
        """
        scheduled_scan_obj = self.scan_input
        scan_id = scheduled_scan_obj.id

        # Initialise output directory
        tool_name = scheduled_scan_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)

        scan_outputs_file = dir_path + os.path.sep + "sqlmap_outputs_" + scan_id
        return luigi.LocalTarget(scan_outputs_file)

    def run(self) -> None:
        """
        Execute the SQLMap SQL injection scanning operation.

        Collects all target URLs via scan_data.get_urls(), launches one SQLMap
        process per URL, captures stdout to individual output files, and writes
        a consolidated JSON manifest for the import phase.

        Returns:
            None: Results are written to the output file specified by self.output()

        Raises:
            RuntimeError: If any SQLMap process exits with a non-zero exit code
        """
        global url_set
        url_set = set()

        scheduled_scan_obj = self.scan_input

        # Resolve output paths
        output_file_path = self.output().path
        output_dir = os.path.dirname(output_file_path)

        url_to_id_map: Dict[str, Dict[str, Any]] = {}

        tool_args = scheduled_scan_obj.current_tool.args
        if tool_args:
            tool_args = tool_args.split()

        # Collect all URLs using the same pattern as NucleiScan / FeroxScan
        endpoint_url_map = scheduled_scan_obj.scan_data.get_urls()

        for url_str, url_metadata in endpoint_url_map.items():
            host_id = url_metadata.get('host_id')
            port_id = url_metadata.get('port_id')

            if url_str and url_str not in url_set:
                url_set.add(url_str)
                rand_str = str(random.randint(1000000, 2000000))
                scan_output_file_path = (
                    output_dir + os.path.sep + "sqlmap_out_" + rand_str
                )
                url_to_id_map[url_str] = {
                    'port_id': port_id,
                    'host_id': host_id,
                    'output_file': scan_output_file_path,
                }

        futures = []
        for target_url, target_meta in url_to_id_map.items():
            scan_output_file_path = target_meta['output_file']

            command = []
            if os.name != 'nt':
                command.append("sudo")

            command.extend([
                "python3",
                SQLMAP_PATH,
                "-u", target_url,
            ])

            if tool_args and len(tool_args) > 0:
                command.extend(tool_args)

            callback_with_tool_id = partial(
                scheduled_scan_obj.register_tool_executor,
                scheduled_scan_obj.current_tool_instance_id,
            )

            futures.append(scan_utils.executor.submit(
                process_wrapper,
                cmd_args=command,
                pid_callback=callback_with_tool_id,
                stdout_file=scan_output_file_path,
            ))

        # Register all futures as a single ToolExecutor
        scan_proc_inst = data_model.ToolExecutor(futures)
        scheduled_scan_obj.register_tool_executor(
            scheduled_scan_obj.current_tool_instance_id, scan_proc_inst
        )

        results_dict = {'url_to_id_map': url_to_id_map}

        # Write manifest file consumed by the import phase
        with open(output_file_path, 'w') as file_fd:
            file_fd.write(json.dumps(results_dict))

        # Wait for all scan processes to complete
        for future in futures:
            ret_dict = future.result()
            if ret_dict and 'exit_code' in ret_dict:
                exit_code = ret_dict['exit_code']
                if exit_code != 0:
                    err_msg = ret_dict.get('stderr', '')
                    logging.getLogger(__name__).error(
                        "SQLMap scan for scan ID %s exited with code %d: %s"
                        % (scheduled_scan_obj.id, exit_code, err_msg)
                    )
                    raise RuntimeError(
                        "SQLMap scan for scan ID %s exited with code %d: %s"
                        % (scheduled_scan_obj.id, exit_code, err_msg)
                    )


def _extract_vuln_details(content: str, url: str) -> str:
    """
    Extract a concise vulnerability description from sqlmap stdout.

    Captures the injection-point summary block that sqlmap prints when it
    identifies a vulnerable parameter.

    Args:
        content (str): Full stdout text captured from sqlmap.
        url (str): Target URL, used as a fallback description.

    Returns:
        str: Multi-line description of the identified injection point(s),
             or a simple fallback string when no block can be extracted.
    """
    lines = content.splitlines()
    details: List[str] = []
    capture = False

    for line in lines:
        stripped = line.strip()
        if 'identified the following injection point' in stripped:
            capture = True
        if capture:
            details.append(stripped)
            # Limit capture to a reasonable block size
            if len(details) > 30:
                break

    if details:
        return '\n'.join(details)
    return "SQL injection detected at: %s" % url


def parse_sqlmap_output(
    output_file: str,
    tool_instance_id: Optional[str] = None,
) -> List[Any]:
    """
    Parse a SQLMap manifest output file and return data_model Record objects.

    Reads the JSON manifest written by SqlmapScan, then for each captured
    stdout file checks whether sqlmap reported an injectable parameter.
    A Vuln record is created for each URL where injection was confirmed.

    Args:
        output_file (str): Path to the JSON manifest file produced by SqlmapScan.
        tool_instance_id (Optional[str]): Value to assign to
            ``collection_tool_instance_id`` on each created record.

    Returns:
        List[Any]: List of data_model.Vuln objects for discovered SQL injections.
                   Returns an empty list when no vulnerabilities were found.
    """
    with open(output_file, 'r') as file_fd:
        data = file_fd.read()

    ret_arr: List[Any] = []

    if not data:
        return ret_arr

    scan_data_dict = json.loads(data)
    url_to_id_map = scan_data_dict.get('url_to_id_map', {})

    for url_str, obj_data in url_to_id_map.items():
        scan_output_file = obj_data['output_file']
        port_id = obj_data['port_id']

        if not os.path.exists(scan_output_file):
            continue

        with open(scan_output_file, 'r') as f:
            content = f.read()

        # sqlmap reports findings with this header when a parameter is vulnerable
        injection_found = (
            'identified the following injection point' in content
            or ('Parameter:' in content and 'Type:' in content)
        )

        if injection_found:
            vuln_obj = data_model.Vuln(parent_id=port_id)
            vuln_obj.collection_tool_instance_id = tool_instance_id
            vuln_obj.name = 'sql_injection'
            vuln_obj.vuln_details = _extract_vuln_details(content, url_str)
            ret_arr.append(vuln_obj)

    return ret_arr


@inherits(SqlmapScan)
class ImportSqlmapOutput(data_model.ImportToolXOutput):
    """
    Luigi task for importing and processing SQLMap scan results.

    This task handles the post-processing of SQLMap scan outputs, parsing
    stdout captures for SQL injection indicators and importing any discovered
    vulnerabilities into the database structure.

    The class inherits from both SqlmapScan (via @inherits decorator) and
    ImportToolXOutput, providing access to scan parameters and import functionality.

    Methods:
        requires: Specifies that SqlmapScan must complete before import
        run: Processes scan output files and imports results to database

    Example:
        >>> import_task = ImportSqlmapOutput(scan_input=scan_obj)
        >>> luigi.build([import_task])  # Runs SqlmapScan then ImportSqlmapOutput
    """

    def requires(self) -> SqlmapScan:
        """
        Define task dependencies for the import operation.

        Ensures that SqlmapScan completes successfully before attempting
        to process and import the scan results.

        Returns:
            SqlmapScan: The scanning task that must complete before import
        """
        return SqlmapScan(scan_input=self.scan_input)

    def run(self) -> None:
        """
        Process and import SQLMap scan results into the database.

        Reads the manifest produced by SqlmapScan, parses each per-URL stdout
        capture for SQL injection indicators, and imports any discovered Vuln
        records via self.import_results().

        Returns:
            None: Results are imported directly into the database via
                  self.import_results()
        """
        scheduled_scan_obj = self.scan_input
        tool_instance_id = scheduled_scan_obj.current_tool_instance_id
        ret_arr = parse_sqlmap_output(self.input().path, tool_instance_id)
        self.import_results(scheduled_scan_obj, ret_arr)
