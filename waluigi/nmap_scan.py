from functools import partial
import json
import os
import shutil
import netaddr
import luigi
import traceback
import time
import logging

from luigi.util import inherits
from libnmap.parser import NmapParser
from waluigi import scan_utils
from waluigi import data_model
from datetime import datetime

logger = logging.getLogger(__name__)

custom_user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"


class Nmap(data_model.WaluigiTool):

    def __init__(self):
        self.name = 'nmap'
        self.description = 'Nmap is a network scanning tool used to discover hosts and services on a computer network. It can be used to perform port scanning, service detection, and OS detection.'
        self.project_url = "https://github.com/nmap/nmap"
        self.collector_type = data_model.CollectorType.ACTIVE.value
        self.scan_order = 6
        self.args = "-sV --script +ssl-cert --script-args ssl=True"
        self.scan_func = Nmap.nmap_scan_func
        self.import_func = Nmap.nmap_import

    @staticmethod
    def nmap_scan_func(scan_input):
        luigi_run_result = luigi.build([NmapScan(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True

    @staticmethod
    def nmap_import(scan_input):
        luigi_run_result = luigi.build([ImportNmapOutput(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


class NmapScan(luigi.Task):

    scan_input = luigi.Parameter()

    def output(self):

        scheduled_scan_obj = self.scan_input
        scan_id = scheduled_scan_obj.id

        # scan_target_dict = scheduled_scan_obj.scan_target_dict
        mod_str = ''
        if scheduled_scan_obj.scan_data.module_id:
            module_id = str(scheduled_scan_obj.scan_data.module_id)
            mod_str = "_" + module_id

        # Init directory
        tool_name = scheduled_scan_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)
        meta_file_path = dir_path + os.path.sep + \
            "nmap_scan_" + scan_id + mod_str + ".meta"

        return luigi.LocalTarget(meta_file_path)

    def run(self):

        scheduled_scan_obj = self.scan_input
        selected_interface = scheduled_scan_obj.selected_interface

        # Ensure output folder exists
        meta_file_path = self.output().path
        dir_path = os.path.dirname(meta_file_path)

        # load input file
        scope_obj = scheduled_scan_obj.scan_data

        nmap_scan_data = None
        nmap_scan_args = scheduled_scan_obj.current_tool.args
        if nmap_scan_args:
            nmap_scan_args = nmap_scan_args.split(" ")

        # Check if massscan was already run
        mass_scan_ran = False
        for collection_tool in scheduled_scan_obj.collection_tool_map.values():
            if collection_tool.collection_tool.name == 'masscan':
                mass_scan_ran = True
                break

        nmap_scan_list = []
        scan_port_map = {}
        if mass_scan_ran:

            # Create scan jobs for each port and only scan the IPs mapped to that port
            target_map = scope_obj.host_port_obj_map
            for target_key in target_map:

                target_obj_dict = target_map[target_key]
                port_obj = target_obj_dict['port_obj']
                port_str = port_obj.port

                host_obj = target_obj_dict['host_obj']
                ip_addr = host_obj.ipv4_addr

                # Get dict for port or create it
                if port_str in scan_port_map:
                    scan_obj = scan_port_map[port_str]
                else:
                    scan_obj = {'port_list': [
                        str(port_str)], 'tool_args': nmap_scan_args}
                    scan_obj['resolve_dns'] = False
                    scan_port_map[port_str] = scan_obj

                # Add the targets
                if 'ip_set' in scan_obj:
                    ip_set = scan_obj['ip_set']
                else:
                    ip_set = set()
                    scan_obj['ip_set'] = ip_set

                # Add IP
                ip_set.add(ip_addr)

                target_arr = target_key.split(":")
                if target_arr[0] != ip_addr:
                    domain_str = target_arr[0]
                    scan_obj['resolve_dns'] = True
                    ip_set.add(domain_str)

                # Add each to the scan list
            nmap_scan_list.extend(list(scan_port_map.values()))

        else:

            # Use original scope for scan
            target_map = scope_obj.host_port_obj_map
            port_num_list = scope_obj.get_port_number_list_from_scope()

            # Use original scope for scan
            # Create scan for each subnet, for all ports to scan
            subnet_map = scope_obj.subnet_map
            if len(subnet_map) > 0:
                for subnet_id in subnet_map:
                    subnet_obj = subnet_map[subnet_id]
                    subnet_str = "%s/%s" % (subnet_obj.subnet, subnet_obj.mask)

                    scan_obj = {}
                    scan_obj['ip_set'] = [subnet_str]
                    scan_obj['tool_args'] = nmap_scan_args
                    scan_obj['resolve_dns'] = False

                    port_set = set()
                    for port_str in port_num_list:
                        port_set.add(port_str)

                    scan_obj['port_list'] = list(port_set)

                    # Add the scan
                    nmap_scan_list.append(scan_obj)

            elif len(target_map) > 0:
                for target_key in target_map:

                    target_obj_dict = target_map[target_key]
                    port_obj = target_obj_dict['port_obj']
                    port_str = port_obj.port

                    host_obj = target_obj_dict['host_obj']
                    ip_addr = host_obj.ipv4_addr

                    # Get dict for port or create it
                    if port_str in scan_port_map:
                        scan_obj = scan_port_map[port_str]
                    else:
                        scan_obj = {'port_list': [
                            str(port_str)], 'tool_args': nmap_scan_args}
                        scan_obj['resolve_dns'] = False
                        scan_port_map[port_str] = scan_obj

                    # Add the targets
                    if 'ip_set' in scan_obj:
                        ip_set = scan_obj['ip_set']
                    else:
                        ip_set = set()
                        scan_obj['ip_set'] = ip_set

                    # Add IP
                    ip_set.add(ip_addr)

                    target_arr = target_key.split(":")
                    if target_arr[0] != ip_addr:
                        domain_str = target_arr[0]
                        scan_obj['resolve_dns'] = True
                        ip_set.add(domain_str)

                    # Add each to the scan list
                nmap_scan_list.extend(list(scan_port_map.values()))

            else:

                if len(port_num_list) > 0:

                    # Get host map and pair each host with all ports to scan
                    scan_obj = {}
                    target_set = set()
                    resolve_dns = False

                    host_list = scope_obj.get_hosts(
                        [data_model.RecordTag.SCOPE.value, data_model.RecordTag.LOCAL.value])

                    for host_obj in host_list:
                        ip_addr = host_obj.ipv4_addr
                        target_set.add(ip_addr)

                        if host_obj.id in scope_obj.domain_host_id_map:
                            temp_domain_list = scope_obj.domain_host_id_map[host_obj.id]
                            if len(temp_domain_list) > 0:
                                resolve_dns = True
                                for domain_obj in temp_domain_list:

                                    domain_name = domain_obj.name
                                    target_set.add(domain_name)

                    # Add a port entry for each domain
                    domain_list = scope_obj.get_domains(
                        [data_model.RecordTag.SCOPE.value, data_model.RecordTag.LOCAL.value])
                    for domain_obj in domain_list:
                        domain_name = domain_obj.name

                        # Add Domain to list
                        target_set.add(domain_name)

                    scan_obj['ip_set'] = target_set
                    scan_obj['tool_args'] = nmap_scan_args
                    scan_obj['resolve_dns'] = resolve_dns

                    port_set = set()
                    for port_str in port_num_list:
                        port_set.add(port_str)

                    scan_obj['port_list'] = list(port_set)

                    # Add the scan
                    nmap_scan_list.append(scan_obj)

        module_id = None
        mod_str = ''
        if scheduled_scan_obj.scan_data.module_id:
            module_id = str(scheduled_scan_obj.scan_data.module_id)
            mod_str = "_" + module_id

        # Output structure for scan jobs
        nmap_scan_cmd_list = []
        nmap_scan_data = {}

        # Loop through map and create nmap command array
        counter = 0
        futures = []
        for scan_obj in nmap_scan_list:

            nmap_scan_inst = {}
            script_args = None
            port_list = scan_obj['port_list']
            port_comma_list = ','.join(port_list)
            ip_list_path = dir_path + os.path.sep + \
                "nmap_in_" + str(counter) + mod_str

            # Write IPs to a file
            ip_list = scan_obj['ip_set']
            if len(ip_list) == 0:
                continue

            with open(ip_list_path, 'w') as in_file_fd:
                for ip in ip_list:
                    in_file_fd.write(ip + "\n")

            if 'tool_args' in scan_obj:
                script_args = scan_obj['tool_args']

            # Nmap command args
            nmap_output_xml_file = dir_path + os.path.sep + \
                "nmap_out_" + str(counter) + mod_str

            # Add sudo if on linux based system
            command = []
            if os.name != 'nt':
                command.append("sudo")

            command_arr = [
                "nmap",
                "-v",
                "-Pn",
                "--open",
                "--host-timeout",
                "30m",
                "--script-timeout",
                "2m",
                "--script-args",
                'http.useragent="%s"' % custom_user_agent,
                "-sT",
                "-p",
                port_comma_list,
                "-oX",
                nmap_output_xml_file,
                "-iL",
                ip_list_path

            ]

            # Add the specific interface to scan from if its selected
            if selected_interface:
                int_name = selected_interface.name.strip()
                command_arr.extend(['-e', int_name])

            # Add base arguments
            command.extend(command_arr)

            # Should do DNS lookup (HTTP assets)
            resolve_dns = scan_obj['resolve_dns']
            if resolve_dns == False:
                command.append("-n")

            # Add script args
            if script_args and len(script_args) > 0:
                command.extend(script_args)

            # Add to meta data
            nmap_scan_inst['nmap_command'] = command
            nmap_scan_inst['output_file'] = nmap_output_xml_file
            nmap_scan_cmd_list.append(nmap_scan_inst)

            callback_with_tool_id = partial(
                scheduled_scan_obj.register_tool_executor, scheduled_scan_obj.current_tool_instance_id)

            futures.append(scan_utils.executor.submit(
                scan_utils.process_wrapper, cmd_args=command, pid_callback=callback_with_tool_id))
            counter += 1

        # Register futures
        scan_proc_inst = data_model.ToolExecutor(futures)
        scheduled_scan_obj.register_tool_executor(
            scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

        # Wait for the tasks to complete and retrieve results
        for future in futures:
            future.result()

        # Add the command list to the output file
        nmap_scan_data['nmap_scan_list'] = nmap_scan_cmd_list

        # Write out meta data file
        if nmap_scan_data:
            with open(meta_file_path, 'w') as meta_file_fd:
                meta_file_fd.write(json.dumps(nmap_scan_data))


def remove_dups_from_dict(dict_array):
    ret_arr = []

    script_set = set()
    for script_json in dict_array:
        script_entry = json.dumps(script_json)
        script_set.add(script_entry)

    for script_entry in script_set:
        script_json = json.loads(script_entry)
        ret_arr.append(script_json)

    return ret_arr


@inherits(NmapScan)
class ImportNmapOutput(data_model.ImportToolXOutput):

    def requires(self):
        return NmapScan(scan_input=self.scan_input)

    def run(self):

        scheduled_scan_obj = self.scan_input
        tool_instance_id = scheduled_scan_obj.current_tool_instance_id
        scope_obj = scheduled_scan_obj.scan_data
        tool_obj = scheduled_scan_obj.current_tool
        tool_id = tool_obj.id

        ret_arr = []

        meta_file = self.input().path
        if os.path.exists(meta_file):

            with open(meta_file) as file_fd:
                json_input = file_fd.read()

            # load input file
            if len(json_input) > 0:
                nmap_scan_obj = json.loads(json_input)
                nmap_json_arr = nmap_scan_obj['nmap_scan_list']

                for nmap_scan_entry in nmap_json_arr:

                    # For each file
                    nmap_out = nmap_scan_entry['output_file']
                    nmap_report = None
                    try:
                        if os.path.exists(nmap_out) and os.path.getsize(nmap_out) > 0:
                            nmap_report = NmapParser.parse_fromfile(nmap_out)
                        else:
                            logging.getLogger(__name__).warning(
                                f"Skipping nmap output file {nmap_out}: file does not exist or is empty."
                            )
                            continue
                    except Exception as e:
                        logging.getLogger(__name__).error(
                            "Failed parsing nmap output: %s" % nmap_out)
                        logging.getLogger(__name__).error(
                            traceback.format_exc())

                        try:
                            dir_path = os.path.dirname(meta_file)
                            shutil.rmtree(dir_path)
                        except Exception as e:
                            pass

                        raise

                    # Loop through hosts
                    for host in nmap_report.hosts:

                        host_ip = host.id
                        # Get the host entry for the IP address in the results
                        host_id = None

                        # Loop through ports
                        for port in host.get_open_ports():

                            port_str = str(port[0])
                            port_service_id = port[1] + "." + port_str

                            # Check if we have a port_id
                            port_id = None
                            host_key = '%s:%s' % (host_ip, port_str)

                            if host_key in scope_obj.host_port_obj_map:
                                host_port_dict = scope_obj.host_port_obj_map[
                                    host_key]
                                port_id = host_port_dict['port_obj'].id
                                host_id = host_port_dict['host_obj'].id

                            # See if we have a host/port mapping already for this domain and port
                            elif host_ip in scope_obj.host_ip_id_map:
                                host_id = scope_obj.host_ip_id_map[host_ip]

                            # Create Host object if one doesn't exists already
                            ip_object = netaddr.IPAddress(host_ip)

                            host_obj = data_model.Host(id=host_id)
                            host_obj.collection_tool_instance_id = tool_instance_id
                            if ip_object.version == 4:
                                host_obj.ipv4_addr = str(ip_object)
                            elif ip_object.version == 6:
                                host_obj.ipv6_addr = str(ip_object)

                            host_id = host_obj.id

                            # Add host
                            ret_arr.append(host_obj)

                            port_obj = data_model.Port(
                                parent_id=host_id, id=port_id)
                            port_obj.collection_tool_instance_id = tool_instance_id
                            port_obj.proto = 0
                            port_obj.port = port_str
                            port_id = port_obj.id

                            # Add port
                            ret_arr.append(port_obj)

                            # Get hostnames
                            hostnames = host.hostnames
                            for hostname in hostnames:

                                if type(hostname) is dict:
                                    hostname = hostname['name']

                                domain_obj = data_model.Domain(
                                    parent_id=host_id)
                                domain_obj.collection_tool_instance_id = tool_instance_id
                                domain_obj.name = hostname

                                # Add domain
                                ret_arr.append(domain_obj)

                            # Get service details if present
                            svc = host.get_service_byid(port_service_id)
                            if svc:

                                # if svc.banner and len(svc.banner) > 0:
                                #     port_obj['banner'] = svc.banner

                                # Set the service dictionary
                                svc_dict = svc.service_dict
                                if 'name' in svc.service_dict:
                                    service_name = svc.service_dict['name']
                                    if service_name:
                                        component_name = service_name.lower().strip()
                                        if len(component_name) > 0 and component_name != "unknown":
                                            component_obj = data_model.WebComponent(
                                                parent_id=port_id)
                                            component_obj.collection_tool_instance_id = tool_instance_id
                                            component_obj.name = component_name
                                            ret_arr.append(component_obj)

                                if 'product' in svc_dict:
                                    component_name = svc_dict['product']
                                    component_name = component_name.replace(
                                        " httpd", "").lower().strip()
                                    if len(component_name) > 0 and component_name != "unknown":

                                        component_obj = data_model.WebComponent(
                                            parent_id=port_id)
                                        component_obj.collection_tool_instance_id = tool_instance_id
                                        component_obj.name = component_name

                                        # Add the version
                                        if 'version' in svc_dict:
                                            component_version = svc_dict['version']
                                            if len(component_version) > 0:
                                                component_obj.version = component_version

                                        ret_arr.append(component_obj)

                                script_res_arr = svc.scripts_results
                                if len(script_res_arr) > 0:

                                    # Remove dups
                                    script_res = remove_dups_from_dict(
                                        script_res_arr)

                                    # Add domains in certificate to port if SSL
                                    for script in script_res:

                                        script_id = script['id']
                                        if script_id == 'ssl-cert':

                                            if port_obj:
                                                port_obj.secure = True

                                            # Create a certificate object
                                            cert_obj = data_model.Certificate(
                                                parent_id=port_obj.id)
                                            cert_obj.collection_tool_instance_id = tool_instance_id
                                            if 'elements' in script:
                                                elements = script['elements']
                                                if 'validity' in elements:
                                                    validity = elements['validity']
                                                    if 'notBefore' in validity:
                                                        issued = validity['notBefore']

                                                        dt = datetime.strptime(
                                                            issued, '%Y-%m-%dT%H:%M:%S')
                                                        cert_obj.issued = int(
                                                            time.mktime(dt.timetuple()))

                                                    if 'notAfter' in validity:
                                                        expires = validity['notAfter']

                                                        dt = datetime.strptime(
                                                            expires, '%Y-%m-%dT%H:%M:%S')
                                                        cert_obj.expires = int(
                                                            time.mktime(dt.timetuple()))

                                                if 'sha1' in elements:
                                                    fingerprint_hash = elements['sha1']
                                                    cert_obj.fingerprint_hash = fingerprint_hash

                                                if 'subject' in elements:
                                                    subject = elements['subject']
                                                    if 'commonName' in subject:
                                                        common_name = subject['commonName']
                                                        domain_obj = cert_obj.add_domain(
                                                            host_id, common_name, tool_instance_id)
                                                        if domain_obj:
                                                            ret_arr.append(
                                                                domain_obj)

                                                if 'issuer' in elements:
                                                    issuer = elements['issuer']
                                                    cert_obj.issuer = json.dumps(
                                                        issuer)

                                                if 'extensions' in elements:
                                                    extensions = elements['extensions']
                                                    if 'null' in extensions:
                                                        null_ext = extensions['null']
                                                        if not isinstance(null_ext, list):
                                                            null_ext = [
                                                                null_ext]

                                                        for ext_inst in null_ext:
                                                            if 'name' in ext_inst:
                                                                ext_name = ext_inst['name']
                                                                if 'X509v3 Subject Alternative Name' == ext_name:
                                                                    san_value = ext_inst['value']
                                                                    if ":" in san_value:
                                                                        dns_name = san_value.split(":")[
                                                                            1]
                                                                        if "," in dns_name:
                                                                            dns_name = dns_name.split(",")[
                                                                                0]
                                                                        # logging.getLogger(__name__).debug(
                                                                        #    "Adding SAN: %s" % dns_name)
                                                                        domain_obj = cert_obj.add_domain(
                                                                            host_id, dns_name, tool_instance_id)
                                                                        if domain_obj:
                                                                            ret_arr.append(
                                                                                domain_obj)

                                            # Add the cert object
                                            ret_arr.append(cert_obj)

                                        elif 'http' in script_id:
                                            # Set to http if nmap detected http in a script
                                            component_obj = data_model.WebComponent(
                                                parent_id=port_id)
                                            component_obj.collection_tool_instance_id = tool_instance_id
                                            component_obj.name = 'http'
                                            ret_arr.append(component_obj)

                                    # Iterate over script entries
                                    for script_out in script_res:
                                        if 'id' in script_out and 'output' in script_out:

                                            script_id = script_out['id']
                                            output = script_out['output']
                                            if len(output) > 0:

                                                # Add collection module
                                                temp_module_id = None
                                                if scope_obj.module_id:
                                                    temp_module_id = scope_obj.module_id

                                                    # Parse output and add components if present
                                                    output_components = scope_obj.module_outputs
                                                    for output_component in output_components:
                                                        if output_component.name in output.lower():
                                                            component_obj = data_model.WebComponent(
                                                                parent_id=port_id)
                                                            component_obj.collection_tool_instance_id = tool_instance_id
                                                            component_obj.name = output_component.name
                                                            ret_arr.append(
                                                                component_obj)

                                                else:
                                                    args_str = "--script +%s" % script_id
                                                    module_obj = data_model.CollectionModule(
                                                        parent_id=tool_id)
                                                    module_obj.collection_tool_instance_id = tool_instance_id
                                                    module_obj.name = script_id
                                                    module_obj.args = args_str

                                                    ret_arr.append(module_obj)
                                                    temp_module_id = module_obj.id

                                                # Add module output
                                                module_output_obj = data_model.CollectionModuleOutput(
                                                    parent_id=temp_module_id)
                                                module_output_obj.collection_tool_instance_id = tool_instance_id
                                                module_output_obj.data = output
                                                module_output_obj.port_id = port_id

                                                ret_arr.append(
                                                    module_output_obj)

        # Import, Update, & Save
        self.import_results(scheduled_scan_obj, ret_arr)
