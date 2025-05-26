from functools import partial
import json
import os
import luigi
import errno
import logging

from luigi.util import inherits
from waluigi import scan_utils
from waluigi import data_model

custom_user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"


logger = logging.getLogger(__name__)


class Nuclei(data_model.WaluigiTool):

    def __init__(self):
        self.name = 'nuclei'
        self.collector_type = data_model.CollectorType.ACTIVE.value
        self.scan_order = 7
        self.args = "http/technologies/fingerprinthub-web-fingerprints.yaml"
        self.scan_func = Nuclei.nuclei_scan_func
        self.import_func = Nuclei.nuclei_import

    @staticmethod
    def nuclei_scan_func(scan_input):
        luigi_run_result = luigi.build([NucleiScan(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True

    @staticmethod
    def nuclei_import(scan_input):
        luigi_run_result = luigi.build([ImportNucleiOutput(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


class NucleiScan(luigi.Task):

    scan_input = luigi.Parameter()

    def output(self):

        scheduled_scan_obj = self.scan_input
        scan_id = scheduled_scan_obj.id

        #  Init directory
        tool_name = scheduled_scan_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)

        mod_str = ''
        if scheduled_scan_obj.scan_data.module_id:
            module_id = str(scheduled_scan_obj.scan_data.module_id)
            mod_str = "_" + module_id

        nuclei_outputs_file = dir_path + os.path.sep + \
            "nuclei_outputs_" + scan_id + mod_str
        return luigi.LocalTarget(nuclei_outputs_file)

    def run(self):

        scheduled_scan_obj = self.scan_input

        # Make sure template path exists
        my_env = os.environ.copy()
        use_shell = False
        if os.name == 'nt':
            nuclei_template_root = '%%userprofile%%'
            use_shell = True
        else:
            my_env["HOME"] = "/opt"
            nuclei_template_root = '/opt'

        # Get output file path
        output_file_path = self.output().path
        output_dir = os.path.dirname(output_file_path)

        total_endpoint_set = set()
        endpoint_port_obj_map = {}
        nuclei_output_file = None

        template_path_list = [scheduled_scan_obj.current_tool.args]
        target_map = scheduled_scan_obj.scan_data.host_port_obj_map

        for target_key in target_map:

            target_obj_dict = target_map[target_key]
            port_obj = target_obj_dict['port_obj']
            port_id = port_obj.id
            port_str = port_obj.port
            secure_flag = port_obj.secure

            host_obj = target_obj_dict['host_obj']
            ip_addr = host_obj.ipv4_addr
            target_arr = target_key.split(":")

            url_str = scan_utils.construct_url(ip_addr, port_str, secure_flag)
            port_obj_instance = {"port_id": port_id}

            if url_str not in total_endpoint_set:
                endpoint_port_obj_map[url_str] = port_obj_instance
                total_endpoint_set.add(url_str)

            # Add the domain url as well
            if target_arr[0] != ip_addr:
                domain_str = target_arr[0]
                url_str = scan_utils.construct_url(
                    domain_str, port_str, secure_flag)
                if url_str not in total_endpoint_set:
                    endpoint_port_obj_map[url_str] = port_obj_instance
                    total_endpoint_set.add(url_str)

        template_arr = []
        for template_path in template_path_list:

            if template_path:
                template_path = template_path.replace("/", os.path.sep)

                nuclei_template_path = nuclei_template_root + os.path.sep + "nuclei-templates"
                full_template_path = nuclei_template_path + os.path.sep + template_path
                if os.path.exists(full_template_path) == False:
                    logger.error(
                        "Nuclei template path '%s' does not exist" % full_template_path)
                    raise FileNotFoundError(errno.ENOENT, os.strerror(
                        errno.ENOENT), full_template_path)

                template_arr.append("-t")
                template_arr.append(full_template_path)

        # Write to nuclei input file if endpoints exist
        counter = 0
        if len(total_endpoint_set) > 0:

            mod_str = ''
            if scheduled_scan_obj.scan_data.module_id:
                module_id = str(scheduled_scan_obj.scan_data.module_id)
                mod_str = "_" + module_id

            nuclei_scan_input_file_path = (
                output_dir + os.path.sep + "nuclei_scan_in" + mod_str).strip()

            with open(nuclei_scan_input_file_path, 'w') as file_fd:
                for endpoint in total_endpoint_set:
                    file_fd.write(endpoint + '\n')

            # Nmap command args
            nuclei_output_file = output_dir + os.path.sep + \
                "nuclei_scan_out" + mod_str + "_" + str(counter)

            command = []
            if os.name != 'nt':
                command.append("sudo")

            command_inner = [
                "nuclei",
                "-jsonl",
                "-duc",
                "-ni",
                "-pt",  # Limit to HTTP currently
                "http",
                "-rl",  # Rate limit 50
                "50",
                "-l",
                nuclei_scan_input_file_path,
                "-o",
                nuclei_output_file,
            ]

            # Add templates
            command_inner.extend(template_arr)
            command.extend(command_inner)

            callback_with_tool_id = partial(
                scheduled_scan_obj.register_tool_executor, scheduled_scan_obj.current_tool_instance_id)

            future_inst = scan_utils.executor.submit(
                scan_utils.process_wrapper, cmd_args=command, use_shell=use_shell, my_env=my_env, pid_callback=callback_with_tool_id)

            # Wait for it to finish
            future_inst.result()

        results_dict = {'endpoint_port_obj_map': endpoint_port_obj_map,
                        'output_file_path': nuclei_output_file}

        # Write output file
        with open(output_file_path, 'w') as file_fd:
            file_fd.write(json.dumps(results_dict))


@inherits(NucleiScan)
class ImportNucleiOutput(data_model.ImportToolXOutput):

    def requires(self):
        # Requires NucleiScan
        return NucleiScan(scan_input=self.scan_input)

    def run(self):

        scheduled_scan_obj = self.scan_input
        scope_obj = scheduled_scan_obj.scan_data

        # Import the ports to the manager
        tool_id = scheduled_scan_obj.current_tool.id

        nuclei_output_file = self.input().path
        with open(nuclei_output_file, 'r') as file_fd:
            data = file_fd.read()

        # port_arr = []
        ret_arr = []
        if len(data) > 0:
            scan_data_dict = json.loads(data)

            endpoint_port_obj_map = scan_data_dict['endpoint_port_obj_map']

            # if 'output_file_path' in scan_data_dict:
            output_file_path = scan_data_dict['output_file_path']

            # Read nuclei output
            if output_file_path:

                obj_arr = scan_utils.parse_json_blob_file(output_file_path)
                for nuclei_scan_result in obj_arr:

                    if 'url' in nuclei_scan_result:
                        endpoint = nuclei_scan_result['url']

                        # Get the port object that maps to this url
                        if endpoint in endpoint_port_obj_map:
                            port_obj = endpoint_port_obj_map[endpoint]
                            port_id = port_obj['port_id']

                            if 'template-id' in nuclei_scan_result:
                                template_id = nuclei_scan_result['template-id'].lower()
                                if template_id == 'fingerprinthub-web-fingerprints':

                                    matcher_name = nuclei_scan_result['matcher-name'].lower(
                                    )

                                    # Add component
                                    component_obj = data_model.WebComponent(
                                        parent_id=port_id)
                                    component_obj.name = matcher_name
                                    ret_arr.append(component_obj)

                                elif template_id.startswith("cve-"):

                                    # Add vuln
                                    vuln_obj = data_model.Vuln(
                                        parent_id=port_id)
                                    vuln_obj.name = template_id
                                    ret_arr.append(vuln_obj)

                                module_args = None
                                if 'template' in nuclei_scan_result:
                                    module_args = nuclei_scan_result['template']

                                if scope_obj.module_id:
                                    module_id = str(scope_obj.module_id)

                                    # Parse output and add components if present
                                    output_components = scope_obj.module_outputs
                                    for output_component in output_components:
                                        if output_component.name in str(nuclei_scan_result).lower():
                                            component_obj = data_model.WebComponent(
                                                parent_id=port_id)
                                            component_obj.name = output_component.name
                                            ret_arr.append(
                                                component_obj)
                                else:
                                    # Add collection module
                                    module_obj = data_model.CollectionModule(
                                        parent_id=tool_id)
                                    module_obj.name = template_id
                                    module_obj.args = module_args

                                    ret_arr.append(module_obj)
                                    module_id = module_obj.id

                                # Add module output
                                module_output_obj = data_model.CollectionModuleOutput(
                                    parent_id=module_id)
                                module_output_obj.data = nuclei_scan_result
                                module_output_obj.port_id = port_id

                                ret_arr.append(module_output_obj)

                        else:
                            logger.debug("Endpoint not in map: %s %s" %
                                         (endpoint, str(endpoint_port_obj_map)))

        # Import, Update, & Save
        self.import_results(scheduled_scan_obj, ret_arr)
