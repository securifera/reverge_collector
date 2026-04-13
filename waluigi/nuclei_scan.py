"""
Nuclei vulnerability scanning module for the Waluigi framework.

This module provides vulnerability scanning capabilities using Nuclei, a fast and flexible
vulnerability scanner based on YAML templates. It performs automated security scans on
web applications and services to identify potential vulnerabilities and components.

The module focuses on scanning base URLs (root paths) only, filtering out URLs with
specific paths to concentrate vulnerability scanning efforts on the primary endpoints.

The module implements both scanning and data import functionality through Luigi tasks,
supporting modular scanning operations and comprehensive result processing.

Classes:
    Nuclei: Tool configuration class for Nuclei scanner
    NucleiScan: Luigi task for executing Nuclei vulnerability scans
    ImportNucleiOutput: Luigi task for processing and importing Nuclei scan results

"""

import json
import os
from typing import Dict, Any, List, Set, Optional
import logging
import yaml
import traceback

import netaddr
from functools import partial
from urllib.parse import urlparse
from waluigi import scan_utils
from waluigi import data_model
from waluigi.proc_utils import process_wrapper
from waluigi.tool_runner import (
    import_already_done as _import_already_done,
    import_results as _import_results,
)


class Nuclei(data_model.WaluigiTool):
    """
    Nuclei vulnerability scanner tool configuration.

    This class configures the Nuclei vulnerability scanner for integration with the
    Waluigi framework. Nuclei is a fast and flexible vulnerability scanner that uses
    YAML-based templates to identify security issues in web applications and services.

    The tool is configured for active scanning with HTTP technology fingerprinting
    and vulnerability detection capabilities.

    Attributes:
        name (str): Tool identifier name
        description (str): Human-readable tool description
        project_url (str): Official project URL
        collector_type (str): Type of collection (ACTIVE)
        scan_order (int): Execution order in scan chain
        args (str): Default command line arguments
        scan_func (callable): Function to execute scans
        import_func (callable): Function to import results

    Example:
        >>> nuclei_tool = Nuclei()
        >>> print(nuclei_tool.name)
        'nuclei'
        >>> nuclei_tool.scan_func(scan_input)
        True
    """

    def __init__(self) -> None:
        """
        Initialize Nuclei tool configuration.

        Sets up the tool with default parameters for vulnerability scanning,
        including fingerprinting templates and rate limiting.
        """
        super().__init__()
        self.name: str = 'nuclei'
        self.description: str = 'Nuclei is a fast and flexible vulnerability scanner based on simple YAML based DSL. It allows users to create custom templates for scanning various protocols and services.'
        self.project_url: str = 'https://github.com/projectdiscovery/nuclei'
        self.tags = ['vuln-scan', 'slow']
        self.collector_type: str = data_model.CollectorType.ACTIVE.value
        self.scan_order: int = 7
        self.args: str = "-ni -pt http -rl 50 -t http/technologies/fingerprinthub-web-fingerprints.yaml"
        self.input_records = [data_model.ServerRecordType.PORT,
                              data_model.ServerRecordType.HTTP_ENDPOINT_DATA]
        self.output_records = [
            data_model.ServerRecordType.COLLECTION_MODULE,
            data_model.ServerRecordType.COLLECTION_MODULE_OUTPUT,
            data_model.ServerRecordType.WEB_COMPONENT,
            data_model.ServerRecordType.VULNERABILITY
        ]
        self.scan_func = nuclei_scan_func
        self.import_func = nuclei_import
        self.modules_func = Nuclei.nuclei_modules

    @staticmethod
    def nuclei_modules() -> List:
        """
        Retrieve available Nuclei templates as collection modules.

        Executes 'nuclei -tl' to get a list of all available Nuclei templates,
        then executes 'nuclei -td' once to retrieve all YAML template content
        in concatenated format. Parses the concatenated output by matching
        "Template: " entries with template IDs from the list, and extracts
        metadata to convert them to CollectionModule objects.

        Results are cached on disk and only regenerated when the ``.templates-index``
        file changes (i.e. after a ``nuclei -update-templates`` run).

        Returns:
            List[data_model.CollectionModule]: List of collection modules, one for each Nuclei template

        Example:
            >>> nuclei_tool = Nuclei()
            >>> modules = nuclei_tool.modules_func()
            >>> for module in modules:
            ...     print(f"{module.name}: {module.args}")
        """
        from waluigi.module_cache import get_cached_modules
        return get_cached_modules('nuclei', Nuclei._fingerprint,
                                  Nuclei._generate_nuclei_modules)

    @staticmethod
    def _fingerprint() -> Optional[str]:
        """Cache fingerprint: SHA-256 of the .templates-index file."""
        from waluigi.module_cache import sha256_file
        result = process_wrapper(cmd_args=['nuclei', '-tv'], store_output=True)
        if not result or result.get('exit_code', 1) != 0:
            return None
        for line in result.get('stderr', '').split('\n'):
            if 'nuclei-templates version' in line and '(' in line and ')' in line:
                start = line.rfind('(')
                end = line.rfind(')')
                if 0 <= start < end:
                    root = line[start + 1:end].strip()
                    index = os.path.join(root, '.templates-index')
                    if os.path.exists(index):
                        return sha256_file(index)
        return None

    @staticmethod
    def _generate_nuclei_modules() -> List:
        """Internal: enumerate Nuclei templates without cache."""
        modules = []

        try:
            # Execute nuclei -tl to get list of all templates
            cmd_args = ['nuclei', '-tv']
            result = process_wrapper(cmd_args=cmd_args, store_output=True)

            if result and 'exit_code' in result and result['exit_code'] != 0:
                logging.getLogger(__name__).warning(
                    f"nuclei -tl failed with exit code {result['exit_code']}"
                )
                return modules

            # Parse template root path from output
            # Format: "[INF] Public nuclei-templates version: v10.3.6 (/root/nuclei-templates)"
            template_root_path = None
            output_text = result.get('stderr', '') if result else ''
            for line in output_text.split('\n'):
                if 'nuclei-templates version' in line and '(' in line and ')' in line:
                    # Extract the path from parentheses
                    start = line.rfind('(')
                    end = line.rfind(')')
                    if start != -1 and end != -1 and start < end:
                        template_root_path = line[start+1:end].strip()
                    break

            # Parse template list - each line is a template path
            if not template_root_path:
                logging.getLogger(__name__).warning(
                    "No templates found from nuclei -tl")
                return modules

            template_index = template_root_path + "/.templates-index"

            # Read the index file to get list of template IDs and paths
            # Format: template_id,/full/path/to/template.yaml
            try:
                with open(template_index, 'r') as index_file:
                    index_entries = [line.strip()
                                     for line in index_file if line.strip()]
            except Exception as e:
                logging.getLogger(__name__).warning(
                    f"Failed to read template index file {template_index}: {str(e)}"
                )
                return modules

            # Process each template file
            for index_entry in index_entries:
                if not index_entry:
                    continue
                try:
                    # Parse comma-separated format: template_id,/full/path/to/template.yaml
                    parts = index_entry.split(',', 1)
                    if len(parts) != 2:
                        logging.getLogger(__name__).debug(
                            f"Invalid index entry format: {index_entry}"
                        )
                        continue

                    template_id_from_index = parts[0].strip()
                    full_template_path = parts[1].strip()

                    template_path = full_template_path.replace(
                        template_root_path + os.sep, '')

                    # Read only up to the 'variables:' field to minimize overhead
                    yaml_content = ''
                    try:
                        with open(full_template_path, 'r') as template_file:
                            for line in template_file:
                                yaml_content += line
                                # Stop reading once we hit the 'variables:' section
                                if line.strip().startswith('variables:'):
                                    break
                    except Exception as e:
                        logging.getLogger(__name__).debug(
                            f"Failed to read template file {full_template_path}: {str(e)}"
                        )
                        continue

                    if not yaml_content:
                        continue

                    # Parse YAML content (metadata section only)
                    try:
                        template_data = yaml.safe_load(yaml_content)
                    except Exception as e:
                        logging.getLogger(__name__).debug(
                            f"Failed to parse YAML for template {full_template_path}: {str(e)}"
                        )
                        continue

                    if not template_data or not isinstance(template_data, dict):
                        continue

                    # Extract template metadata
                    template_id = template_data.get('id', '')
                    info = template_data.get('info', {})
                    template_name = info.get('name', template_id)
                    template_description = info.get('description', '')

                    if not template_id:
                        continue

                    # Create CollectionModule for this template
                    module = data_model.CollectionModule()
                    module.name = template_id
                    module.description = template_name
                    if template_description:
                        # Clean up description - remove leading/trailing whitespace
                        module.description += ": " + template_description.strip()
                    module.args = f"-t {template_path}"
                    modules.append(module)

                except Exception as e:
                    logging.getLogger(__name__).debug(
                        f"Error processing template {template_path}: {str(e)}"
                    )
                    continue

        except Exception as e:
            logging.getLogger(__name__).error(
                f"Error getting nuclei modules: {str(e)}"
            )
            logging.getLogger(__name__).debug(traceback.format_exc())

        return modules


def get_output_path(scan_input) -> str:
    scan_id: str = scan_input.id
    tool_name: str = scan_input.current_tool.name
    dir_path: str = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)
    return dir_path + os.path.sep + "nuclei_outputs_" + scan_id


def execute_scan(scan_input) -> None:
    output_file_path: str = get_output_path(scan_input)
    if os.path.exists(output_file_path):
        return

    scheduled_scan_obj = scan_input
    output_dir: str = os.path.dirname(output_file_path)

    my_env: Dict[str, str] = os.environ.copy()
    use_shell: bool = False
    if os.name == 'nt':
        use_shell = True
    else:
        my_env["HOME"] = "/opt"

    nuclei_output_file: Optional[str] = None

    custom_args: Optional[List[str]] = None
    if scheduled_scan_obj.current_tool.args:
        custom_args = scheduled_scan_obj.current_tool.args.split(" ")

    all_endpoint_port_obj_map = scheduled_scan_obj.scan_data.get_urls()
    endpoint_port_obj_map = {}
    for url, port_data in all_endpoint_port_obj_map.items():
        if port_data.get('path') is None or port_data.get('path') == '/':
            endpoint_port_obj_map[url] = port_data

    total_endpoint_set = set(endpoint_port_obj_map.keys())

    counter: int = 0
    if len(total_endpoint_set) > 0:
        nuclei_scan_input_file_path: str = (
            output_dir + os.path.sep + "nuclei_scan_in").strip()

        with open(nuclei_scan_input_file_path, 'w') as file_fd:
            for endpoint in total_endpoint_set:
                file_fd.write(endpoint + '\n')

        nuclei_output_file = output_dir + os.path.sep + \
            "nuclei_scan_out" + "_" + str(counter)

        command: List[str] = []
        if os.name != 'nt':
            command.append("sudo")

        command_inner: List[str] = [
            "nuclei",
            "-jsonl",
            "-l",
            nuclei_scan_input_file_path,
            "-o",
            nuclei_output_file,
        ]
        if custom_args:
            command_inner.extend(custom_args)
        command.extend(command_inner)

        callback_with_tool_id = partial(
            scheduled_scan_obj.register_tool_executor, scheduled_scan_obj.current_tool_instance_id)

        future_inst = scan_utils.executor.submit(
            process_wrapper, cmd_args=command, use_shell=use_shell, my_env=my_env, pid_callback=callback_with_tool_id)

        ret_dict = future_inst.result()
        if ret_dict and 'exit_code' in ret_dict:
            exit_code = ret_dict['exit_code']
            if exit_code != 0:
                err_msg = ''
                if 'stderr' in ret_dict and ret_dict['stderr']:
                    err_msg = ret_dict['stderr']
                logging.getLogger(__name__).error(
                    "Nuclei scan for scan ID %s exited with code %d: %s" % (scheduled_scan_obj.id, exit_code, err_msg))
                raise RuntimeError("Nuclei scan for scan ID %s exited with code %d: %s" % (
                    scheduled_scan_obj.id, exit_code, err_msg))

    results_dict: Dict[str, Any] = {
        'endpoint_port_obj_map': endpoint_port_obj_map,
        'output_file_path': nuclei_output_file
    }
    with open(output_file_path, 'w') as file_fd:
        file_fd.write(json.dumps(results_dict))


def nuclei_scan_func(scan_input) -> bool:
    try:
        execute_scan(scan_input)
        return True
    except Exception as e:
        logging.getLogger(__name__).error(
            "nuclei scan failed: %s", e, exc_info=True)
        return False


def nuclei_import(scan_input) -> bool:
    try:
        output_path = get_output_path(scan_input)
        if not os.path.exists(output_path):
            return True
        if _import_already_done(scan_input, output_path):
            return True
        scheduled_scan_obj = scan_input
        tool_instance_id = scheduled_scan_obj.current_tool_instance_id
        scope_obj = scheduled_scan_obj.scan_data
        tool_id = scheduled_scan_obj.current_tool.id
        with open(output_path, 'r') as file_fd:
            data = file_fd.read()
        ret_arr: List[Any] = []
        if len(data) > 0:
            scan_data_dict = json.loads(data)
            endpoint_port_obj_map = scan_data_dict['endpoint_port_obj_map']
            output_file_path = scan_data_dict.get('output_file_path')
            if output_file_path:
                ret_arr = parse_nuclei_output(
                    output_file_path, endpoint_port_obj_map,
                    tool_instance_id, tool_id, scope_obj)
        _import_results(scan_input, ret_arr, output_path)
        return True
    except Exception as e:
        logging.getLogger(__name__).error(
            "nuclei import failed: %s", e, exc_info=True)
        return False


def parse_nuclei_output(
    output_file: str,
    endpoint_port_obj_map: Optional[Dict[str, Any]] = None,
    tool_instance_id: Optional[str] = None,
    tool_id: Optional[str] = None,
    scope_obj: Optional[Any] = None,
) -> List[Any]:
    """Parse a Nuclei JSON output file and return data_model Record objects.

    Args:
        output_file:          Path to the Nuclei JSON output file.
        endpoint_port_obj_map: URL-to-port mapping from the Luigi metadata file.
                               When ``None`` (standalone/MCP use), host and port
                               objects are derived from the result URL.
        tool_instance_id:     Value for ``collection_tool_instance_id`` on each record.
        tool_id:              Parent tool ID for CollectionModule records.
        scope_obj:            Optional scan data for module-output correlation.

    Returns:
        List of data_model Record objects.
    """
    ret_arr: List[Any] = []
    obj_arr = scan_utils.parse_json_blob_file(output_file)

    for nuclei_scan_result in obj_arr:
        if 'url' not in nuclei_scan_result:
            continue

        endpoint: str = nuclei_scan_result['url']
        port_id = None

        if endpoint_port_obj_map is not None:
            if endpoint not in endpoint_port_obj_map:
                logging.getLogger(__name__).debug(
                    "Endpoint not in map: %s %s" % (endpoint, str(endpoint_port_obj_map)))
                continue
            port_id = endpoint_port_obj_map[endpoint]['port_id']
        else:
            # Standalone: build host/port from the result URL
            parsed_url = urlparse(endpoint)
            hostname = parsed_url.hostname
            port_num = parsed_url.port or (
                443 if parsed_url.scheme == 'https' else 80)

            host_obj = data_model.Host()
            host_obj.collection_tool_instance_id = tool_instance_id
            try:
                ip_object = netaddr.IPAddress(hostname)
                if ip_object.version == 4:
                    host_obj.ipv4_addr = str(ip_object)
                else:
                    host_obj.ipv6_addr = str(ip_object)
            except (netaddr.core.AddrFormatError, TypeError):
                pass
            ret_arr.append(host_obj)

            port_data_obj = data_model.Port(parent_id=host_obj.id)
            port_data_obj.collection_tool_instance_id = tool_instance_id
            port_data_obj.proto = 0
            port_data_obj.port = str(port_num)
            if parsed_url.scheme == 'https':
                port_data_obj.secure = True
            ret_arr.append(port_data_obj)
            port_id = port_data_obj.id

        if 'template-id' not in nuclei_scan_result:
            continue

        template_id: str = nuclei_scan_result['template-id'].lower()

        if template_id == 'fingerprinthub-web-fingerprints':
            if 'matcher-name' in nuclei_scan_result:
                component_obj = data_model.WebComponent(parent_id=port_id)
                component_obj.collection_tool_instance_id = tool_instance_id
                component_obj.name = nuclei_scan_result['matcher-name'].lower()
                ret_arr.append(component_obj)

        elif template_id.startswith("cve-"):
            vuln_obj = data_model.Vuln(parent_id=port_id)
            vuln_obj.collection_tool_instance_id = tool_instance_id
            vuln_obj.name = template_id
            ret_arr.append(vuln_obj)

        module_args: Optional[str] = nuclei_scan_result.get('template')
        module_obj = data_model.CollectionModule(parent_id=tool_id)
        module_obj.collection_tool_instance_id = tool_instance_id
        module_obj.name = template_id
        module_obj.args = module_args
        ret_arr.append(module_obj)
        module_id = module_obj.id

        if module_id:
            module_output_obj = data_model.CollectionModuleOutput(
                parent_id=module_id)
            module_output_obj.collection_tool_instance_id = tool_instance_id
            module_output_obj.output = nuclei_scan_result
            module_output_obj.port_id = port_id
            ret_arr.append(module_output_obj)

    return ret_arr
