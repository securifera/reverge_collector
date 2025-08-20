"""
Gau (getallurls) Passive URL Enumeration Module for the Waluigi Framework.

This module provides passive URL enumeration capabilities using Gau (getallurls),
a tool that fetches known URLs from sources such as AlienVault's Open Threat Exchange,
the Wayback Machine, Common Crawl, and URLScan for any given domain. Gau is inspired
by Tomnomnom's waybackurls and is designed for large-scale web asset discovery.

The module integrates with the Waluigi framework to automate the collection of historical
and public URLs for scoped domains, supporting both scanning and import workflows.

Features:
    - Passive enumeration of URLs for scoped domains
    - Integration with multiple public data sources
    - Efficient batch processing of domain lists
    - Structured output for downstream analysis and import
    - Luigi-based workflow orchestration

Classes:
    Gau: Main tool class implementing the passive URL enumeration interface
    GauScan: Luigi task for executing Gau scans
    GauImport: Luigi task for importing and processing Gau scan results

Functions:
    None (all logic is encapsulated in classes)

Global Variables:
    None (all state is managed within Luigi tasks and tool classes)

Example:
    Basic usage through the Waluigi framework::
        
        # Initialize the tool
        gau = Gau()
        
        # Execute passive URL enumeration
        success = gau.scan_func(scan_input_obj)
        
        # Import results
        imported = gau.import_func(scan_input_obj)

Note:
    This module performs passive enumeration only and does not actively probe targets.
    It should be used to supplement active scanning workflows with historical and public
    URL data for comprehensive web asset coverage.
    Gau requires internet access to query public data sources and may be subject to
    rate limits or API restrictions.

"""

import json
import os
import netaddr
import luigi
import traceback
import os.path
import logging
import hashlib
import binascii

from typing import List, Dict, Set, Optional, Any, Tuple
from functools import partial
from luigi.util import inherits
from waluigi import scan_utils
from waluigi import data_model
from urllib.parse import urlparse
from waluigi.proc_utils import process_wrapper


class Gau(data_model.WaluigiTool):
    """
    Gau Tool Class for Passive URL Enumeration.

    This class implements the interface for the Gau (getallurls) tool within the Waluigi framework.
    It provides configuration, metadata, and scan/import function bindings for passive URL enumeration
    using public data sources. The Gau tool fetches known URLs for domains, supporting asset discovery
    and historical analysis.

    Attributes:
        name (str): Tool name identifier ('gau').
        description (str): Description of the tool and its data sources.
        project_url (str): URL to the Gau project repository.
        collector_type (str): Collector type (PASSIVE).
        scan_order (int): Execution order for scanning.
        args (str): Default command-line arguments for Gau execution.
        input_records (List): Types of input records accepted (DOMAIN).
        output_records (List): Types of output records produced (DOMAIN, LIST_ITEM, HTTP_ENDPOINT, HTTP_ENDPOINT_DATA).
        scan_func (Callable): Bound function for scan execution.
        import_func (Callable): Bound function for import execution.
    """

    def __init__(self) -> None:
        """
        Initialize the Gau tool class with default configuration and metadata.

        Sets up tool name, description, project URL, collector type, scan order, default arguments,
        input/output record types, and binds scan/import functions for Luigi workflow integration.
        """
        self.name = 'gau'
        self.description = "getallurls (gau) fetches known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, Common Crawl, and URLScan for any given domain. Inspired by Tomnomnom's waybackurls."
        self.project_url = 'https://github.com/lc/gau'
        self.collector_type = data_model.CollectorType.PASSIVE.value
        self.scan_order = 1
        # self.args = "--blacklist .png,.jpg,.gif,.ttf,.woff,.svg --retries 3 --timeout 5 --subs"
        self.args = "--retries 3 --timeout 5 --subs"
        self.input_records = [data_model.ServerRecordType.DOMAIN]
        self.output_records = [
            data_model.ServerRecordType.DOMAIN,
            data_model.ServerRecordType.LIST_ITEM,
            data_model.ServerRecordType.HTTP_ENDPOINT,
            data_model.ServerRecordType.HTTP_ENDPOINT_DATA
        ]
        self.scan_func = Gau.gau_lookup
        self.import_func = Gau.gau_import

    @staticmethod
    def gau_lookup(scan_input: Any) -> bool:
        """
        Execute a Gau scan using Luigi workflow.

        Args:
            scan_input (Any): Input object containing scan parameters and context.

        Returns:
            bool: True if the scan completed successfully, False otherwise.

        This method triggers the GauScan Luigi task, which performs passive URL enumeration
        for the provided domains. The scan results are written to output files for later import.
        """
        luigi_run_result = luigi.build([GauScan(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True

    @staticmethod
    def gau_import(scan_input: Any) -> bool:
        """
        Import Gau scan results using Luigi workflow.

        Args:
            scan_input (Any): Input object containing scan parameters and context.

        Returns:
            bool: True if the import completed successfully, False otherwise.

        This method triggers the GauImport Luigi task, which processes Gau scan output files
        and imports discovered URLs, endpoints, and related data into the Waluigi data model.
        """
        luigi_run_result = luigi.build([GauImport(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


class GauScan(luigi.Task):
    """
    Luigi Task for Executing Gau Passive URL Enumeration.

    This task runs the Gau tool to fetch known URLs for a list of scoped domains. It manages
    input preparation, output file handling, and process execution, integrating with the Waluigi
    scan scheduling and data model.

    Parameters:
        scan_input (luigi.Parameter): Input object containing scan context and parameters.

    Output:
        luigi.LocalTarget: Path to the Gau scan metadata output file (JSON).
    """

    scan_input = luigi.Parameter()

    def output(self) -> luigi.LocalTarget:
        """
        Define the output target for the Gau scan task.

        Returns:
            luigi.LocalTarget: File target for Gau scan metadata output (JSON).

        This method constructs the output file path based on the scan ID and tool name,
        ensuring results are stored in the appropriate directory for downstream import.
        """

        scheduled_scan_obj = self.scan_input
        scan_id = scheduled_scan_obj.id

        # Init directory
        tool_name = scheduled_scan_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)

        # path to input file
        scan_outputs_file = f"{dir_path}{os.path.sep}{tool_name}_meta_{scan_id}.json"
        return luigi.LocalTarget(scan_outputs_file)

    def run(self) -> None:
        """
        Execute the Gau scan process for scoped domains.

        This method prepares the domain list, configures environment variables, builds the Gau
        command, and submits the process for execution. Results are written to output files,
        and errors are logged and raised as needed. Integrates with Waluigi's scan_utils and
        data_model for process management and result tracking.
        """

        scheduled_scan_obj = self.scan_input
        scope_obj = scheduled_scan_obj.scan_data
        domain_list = scope_obj.get_domains(
            [data_model.RecordTag.SCOPE.value, data_model.RecordTag.LOCAL.value])

        # Create a list of domains to pass to gau
        domain_host_map = {}
        for domain in domain_list:
            domain_host_map[domain.name] = domain.parent.id
        domain_list_str = '\n'.join(domain_host_map.keys())

        tool_args = scheduled_scan_obj.current_tool.args
        if tool_args:
            tool_args = tool_args.split(" ")

        # Ensure output folder exists
        gau_meta_file_path = self.output().path
        dir_path = os.path.dirname(gau_meta_file_path)
        gau_scan_output_path = f"{dir_path}{os.path.sep}{scheduled_scan_obj.current_tool.name}_outputs_{scheduled_scan_obj.id}.json"

        # Add env variables for HOME
        my_env = os.environ.copy()

        if os.name != 'nt':
            home_dir = os.path.expanduser('~')
            my_env["HOME"] = home_dir

        # Add the lines
        if len(domain_list) > 0:

            command = []
            command_arr = [
                "gau",
                "--json",
                "--o",
                gau_scan_output_path,
            ]

            command.extend(command_arr)

            # Add script args
            if tool_args and len(tool_args) > 0:
                command.extend(tool_args)

            callback_with_tool_id = partial(
                scheduled_scan_obj.register_tool_executor, scheduled_scan_obj.current_tool_instance_id)

            # Add process dict to process array
            future = scan_utils.executor.submit(
                process_wrapper, cmd_args=command, pid_callback=callback_with_tool_id, stdin_data=domain_list_str, my_env=my_env, print_output=False, store_output=False)

            # Register futures
            scan_proc_inst = data_model.ToolExecutor([future])
            scheduled_scan_obj.register_tool_executor(
                scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

            ret_dict = future.result()
            if ret_dict and 'exit_code' in ret_dict:
                exit_code = ret_dict['exit_code']
                if exit_code != 0:
                    err_msg = ''
                    if 'stderr' in ret_dict and ret_dict['stderr']:
                        err_msg = ret_dict['stderr']
                    logging.getLogger(__name__).error(
                        "Gau scan for scan ID %s exited with code %d: %s" % (scheduled_scan_obj.id, exit_code, err_msg))
                    raise RuntimeError("Gau scan for scan ID %s exited with code %d: %s" % (
                        scheduled_scan_obj.id, exit_code, err_msg))

            # Write the output file
            with open(gau_meta_file_path, 'w') as output_fd:
                output_fd.write(json.dumps(
                    {'domain_map': domain_host_map, 'output_file': gau_scan_output_path}))


@inherits(GauScan)
class GauImport(data_model.ImportToolXOutput):
    """
    Luigi Task for Importing Gau Scan Results.

    This task processes the output files generated by GauScan, parsing discovered URLs and
    endpoints, resolving domains, and importing structured data into the Waluigi data model.
    It supports enrichment of scan results with host, domain, path, port, and endpoint objects.
    """

    def requires(self) -> GauScan:
        """
        Specify the required GauScan task dependency.

        Returns:
            GauScan: The GauScan task instance that must be completed prior to import.

        Ensures that GauImport only runs after the corresponding GauScan task has produced
        its output files.
        """

        # Requires GauScan Task to be run prior
        return GauScan(scan_input=self.scan_input)

    def run(self) -> None:
        """
        Process and import Gau scan results into the Waluigi data model.

        This method reads Gau scan output files, parses URLs, resolves domains, and creates
        Host, Domain, ListItem, Port, HttpEndpoint, and HttpEndpointData objects as needed.
        Results are imported and associated with the current scan context. Handles error
        conditions, DNS resolution, and object deduplication for robust data ingestion.
        """

        scheduled_scan_obj = self.scan_input
        tool_instance_id = scheduled_scan_obj.current_tool_instance_id

        # Read the output file
        hash_alg = hashlib.sha1
        path_hash_map = {}
        domain_name_id_map = {}

        gau_meta_file_path = self.input().path
        with open(gau_meta_file_path, 'r') as file_fd:
            data = file_fd.read()

        domain_map = {}
        ret_arr = []
        if len(data) > 0:
            data_obj = json.loads(data)

            if 'domain_map' in data_obj:
                domain_map = data_obj['domain_map']

            if 'output_file' in data_obj:
                gau_output_file_path = data_obj['output_file']

                with open(gau_output_file_path, 'r') as file_fd:
                    for line in file_fd:
                        if not line.strip():
                            continue

                        url_entry = json.loads(line)
                        if 'url' in url_entry:
                            endpoint_url = url_entry['url']

                            u = urlparse(endpoint_url)
                            web_path_str = u.path
                            if web_path_str and len(web_path_str) > 0:
                                hashobj = hash_alg()
                                hashobj.update(web_path_str.encode())
                                path_hash = hashobj.digest()
                                web_path_hash = binascii.hexlify(
                                    path_hash).decode()

                            host = u.netloc
                            if ":" in host:
                                host_arr = host.split(":")
                                domain_str = host_arr[0].lower()
                            else:
                                domain_str = host.lower()

                            # Check if the domain is an IP adress
                            endpoint_domain_id = None
                            try:
                                netaddr.IPAddress(domain_str)
                            except Exception as e:

                                if domain_str in domain_name_id_map:
                                    endpoint_domain_id = domain_name_id_map[domain_str]
                                else:

                                    if domain_str in domain_map:
                                        host_id = domain_map[domain_str]
                                    else:
                                        ret_list = scan_utils.dns_wrapper(
                                            set([domain_str]))
                                        if ret_list and len(ret_list) > 0:
                                            logging.getLogger(__name__).warning(
                                                f"Domain {domain_str} not found in domain map from gau scan output. Resolved via DNS: {ret_list[0]['ip']}")

                                            ip_object = ret_list[0]
                                            host_obj = data_model.Host()
                                            host_obj.collection_tool_instance_id = tool_instance_id

                                            # Set appropriate IP address field based on version
                                            host_obj.ipv4_addr = ip_object['ip']
                                            ret_arr.append(host_obj)
                                            host_id = host_obj.id
                                            domain_map[domain_str] = host_id

                                    domain_obj = data_model.Domain(
                                        parent_id=host_id)
                                    domain_obj.collection_tool_instance_id = tool_instance_id
                                    domain_obj.name = domain_str

                                    # Add domain
                                    ret_arr.append(domain_obj)
                                    # Set endpoint id
                                    endpoint_domain_id = domain_obj.id
                                    domain_name_id_map[domain_str] = endpoint_domain_id

                                    # Add domain
                                    ret_arr.append(domain_obj)

                            if web_path_hash in path_hash_map:
                                path_obj = path_hash_map[web_path_hash]
                            else:
                                path_obj = data_model.ListItem()
                                path_obj.collection_tool_instance_id = tool_instance_id
                                path_obj.web_path = web_path_str
                                path_obj.web_path_hash = web_path_hash

                                # Add to map and the object list
                                path_hash_map[web_path_hash] = path_obj
                                ret_arr.append(path_obj)

                            web_path_id = path_obj.id

                            # Create Port object
                            port_str = str(u.port) if u.port else (
                                '443' if u.scheme == 'https' else '80')
                            secure = u.scheme == 'https'

                            port_obj = data_model.Port(
                                parent_id=host_id)
                            port_obj.collection_tool_instance_id = tool_instance_id
                            port_obj.proto = 0
                            port_obj.port = port_str
                            port_obj.secure = secure

                            # Add port
                            ret_arr.append(port_obj)

                            # Create http endpoint
                            http_endpoint_obj = data_model.HttpEndpoint(
                                parent_id=port_obj.id)
                            http_endpoint_obj.collection_tool_instance_id = tool_instance_id
                            http_endpoint_obj.web_path_id = web_path_id

                            # Add the endpoint
                            ret_arr.append(http_endpoint_obj)

                            http_endpoint_data_obj = data_model.HttpEndpointData(
                                parent_id=http_endpoint_obj.id)
                            http_endpoint_data_obj.collection_tool_instance_id = tool_instance_id
                            http_endpoint_data_obj.domain_id = endpoint_domain_id

                            # Add the endpoint
                            ret_arr.append(http_endpoint_data_obj)

        scheduled_scan_obj = self.scan_input
        self.import_results(scheduled_scan_obj, ret_arr)
