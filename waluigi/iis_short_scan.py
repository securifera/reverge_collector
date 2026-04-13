import os
import logging
import json

from typing import Dict, Any, List, Set, Optional
from waluigi import scan_utils
from waluigi import data_model
from iis_shortname_scan import Scanner
from waluigi.tool_spec import ToolSpec


class IISShortnameScanner(ToolSpec):

    name = 'iis_short_scan'
    description = 'IIS Shortname Scanner is a tool for discovering short filenames on IIS servers.'
    project_url = 'https://github.com/lijiejie/IIS_shortname_Scanner'
    tags = ['vuln-scan', 'http-crawl']
    collector_type = data_model.CollectorType.ACTIVE.value
    scan_order = 8
    args = ""
    input_records = [data_model.ServerRecordType.PORT,
                     data_model.ServerRecordType.HTTP_ENDPOINT_DATA]
    output_records = [
        data_model.ServerRecordType.COLLECTION_MODULE,
        data_model.ServerRecordType.COLLECTION_MODULE_OUTPUT,
    ]

    def execute_scan(self, scan_input: data_model.ScheduledScan) -> None:
        execute_scan(scan_input)

    def parse_output(self, output_path: str, scan_input: data_model.ScheduledScan) -> list:
        return parse_iis_short_scan_output(
            output_path,
            scan_input.current_tool_instance_id,
            scan_input.current_tool.id,
        )


def iis_short_scan_wrap(target_url_list: List[str]) -> List[Dict[str, Any]]:
    """
    Wrapper function to run IIS shortname scan on a list of target URLs.

    Args:
        target_url_list (List[str]): List of target URLs to scan.
    Returns:
        List[Dict[str, Any]]: List of scan results for each target URL.
    """
    return_list = []
    for target_url in target_url_list:
        try:
            with Scanner(target_url, silent=True) as scanner:
                if not scanner.is_vulnerable():
                    return_list.append({
                        'target': target_url,
                        'vulnerable': False,
                        'files': [],
                        'dirs': []
                    })
                    continue

                # Run the scanner
                scanner.run()

                return_list.append({
                    'target': target_url,
                    'vulnerable': True,
                    'files': scanner.files.copy(),
                    'dirs': scanner.dirs.copy()
                })
        except Exception as e:
            logging.getLogger(__name__).warning(
                f"Error scanning target {target_url}: {e}")
            return_list.append({
                'target': target_url,
                'vulnerable': False,
                'error': str(e),
                'files': [],
                'dirs': []
            })

    return return_list


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

    # Attempt to get all urls first
    all_endpoint_port_obj_map = scope_obj.get_urls()
    endpoint_port_obj_map = {}

    # Filter URLs to only include base URLs (path is None or "/")
    for url, port_data in all_endpoint_port_obj_map.items():
        # Only include URLs with no specific path or root path
        if port_data.get('path') is None or port_data.get('path').endswith('/'):
            endpoint_port_obj_map[url] = port_data

    url_set = set()
    port_id_results_map: Dict[int, List[Dict[str, Any]]] = {}
    if len(endpoint_port_obj_map) > 0:

        futures: List[Any] = []
        port_id_target_map = {}
        for target_url in endpoint_port_obj_map:

            if target_url in url_set:
                continue  # Skip if already processed

            port_data = endpoint_port_obj_map[target_url]
            port_id = port_data.get('port_id', None)
            if port_id is None:
                logging.getLogger(__name__).warning(
                    f"Port ID not found for URL {target_url}. Skipping scan execution.")
                continue

            if port_id not in port_id_target_map:
                port_target_map = {}
                port_id_target_map[port_id] = port_target_map
            else:
                port_target_map = port_id_target_map[port_id]

            port_target_map[target_url] = port_data
            # Add the URL to the set to avoid duplicates
            url_set.add(target_url)

        # Queue up scans
        for port_id, port_target_map in port_id_target_map.items():
            target_list = list(port_target_map.keys())
            future_inst = scan_utils.executor.submit(
                iis_short_scan_wrap, target_url_list=target_list)
            futures.append((future_inst, port_id))

        # Wait for scan completion
        for future_inst, port_id in futures:
            port_target_map = port_id_target_map.get(port_id, {})
            scan_result = future_inst.result()
            for result in scan_result:
                target_url = result['target']
                port_data = port_target_map.get(target_url, {})
                if not port_data:
                    continue

                if port_id not in port_id_results_map:
                    port_results_inst = {
                        'meta_data': port_data, 'results': []}
                    port_id_results_map[port_id] = port_results_inst
                else:
                    port_results_inst = port_id_results_map[port_id]

                if scan_result:
                    port_results_inst['results'].append(result)

    else:
        raise RuntimeError(
            "No ports found for Python scan. Skipping scan execution.")

    # Write output file
    with open(output_file_path, 'w') as file_fd:
        file_fd.write(json.dumps(port_id_results_map))


def parse_iis_short_scan_output(
    output_file: str,
    tool_instance_id: Optional[str] = None,
    tool_id: Optional[str] = None,
) -> List[Any]:
    """Parse an IIS Shortname Scanner JSON output file and return data_model Record objects."""

    with open(output_file, 'r') as file_fd:
        data = file_fd.read()

    ret_arr: List[Any] = []
    if len(data) > 0:
        module_obj = data_model.CollectionModule(parent_id=tool_id)
        module_obj.collection_tool_instance_id = tool_instance_id
        module_obj.name = "iis-shortname-scan"
        module_obj.args = ''
        ret_arr.append(module_obj)
        module_id = module_obj.id

        result_map = json.loads(data)
        for port_id in result_map.keys():
            result_entry = result_map[port_id]
            result_meta_data = result_entry.get('meta_data', [])
            host_id = result_meta_data.get('host_id', None)
            ip_addr = result_meta_data.get('ip_addr', None)
            port_str = result_meta_data.get('port_str', None)
            result_entry_list = result_entry.get('results', [])

            host_obj = data_model.Host(id=host_id)
            host_obj.collection_tool_instance_id = tool_instance_id
            host_obj.ipv4_addr = ip_addr
            ret_arr.append(host_obj)

            port_obj = data_model.Port(parent_id=host_id, id=port_id)
            port_obj.collection_tool_instance_id = tool_instance_id
            port_obj.proto = 0
            port_obj.port = port_str
            ret_arr.append(port_obj)

            if module_id:
                module_output_obj = data_model.CollectionModuleOutput(
                    parent_id=module_id)
                module_output_obj.collection_tool_instance_id = tool_instance_id
                module_output_obj.output = json.dumps(result_entry_list)
                module_output_obj.port_id = port_id
                ret_arr.append(module_output_obj)

    return ret_arr
