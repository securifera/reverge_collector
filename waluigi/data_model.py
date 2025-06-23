import base64
import binascii
import enum
import hashlib
import uuid
import netaddr
import luigi
import os
import json
import importlib
import logging
import traceback

from waluigi import scan_utils

waluigi_tools = [
    ('waluigi.masscan', 'Masscan'),
    ('waluigi.nmap_scan', 'Nmap'),
    ('waluigi.pyshot_scan', 'Pyshot'),
    ('waluigi.nuclei_scan', 'Nuclei'),
    ('waluigi.subfinder_scan', 'Subfinder'),
    ('waluigi.feroxbuster_scan', 'Feroxbuster'),
    ('waluigi.shodan_lookup', 'Shodan'),
    ('waluigi.httpx_scan', 'Httpx'),
    ('waluigi.sectrails_ip_lookup', 'Sectrails'),
    ('waluigi.module_scan', 'Module'),
    ('waluigi.badsecrets_scan', 'Badsecrets'),
    ('waluigi.webcap_scan', 'Webcap')
    # ('waluigi.divvycloud_lookup', 'Divvycloud')
]

wordlist_path = "/tmp/reverge_wordlist"
if not os.path.exists(wordlist_path):
    os.mkdir(wordlist_path)


def get_tool_classes():
    tool_classes = []

    for module_name, class_name in waluigi_tools:
        module = importlib.import_module(module_name)
        tool_class = getattr(module, class_name)
        tool_classes.append(tool_class)
    return tool_classes


def update_host_port_obj_map(scan_data, port_id, host_port_obj_map):

    tag_list = [RecordTag.SCOPE.value, RecordTag.LOCAL.value]

    port_obj = scan_data.port_map[port_id]
    # Exclude ports that originated remotely that aren't part of the scope
    if len(port_obj.tags.intersection(set(tag_list))) == 0:
        return

    # logging.getLogger(__name__).debug("Processing port: %s" % port_obj.to_jsonable())
    host_id = port_obj.parent.id
    if host_id in scan_data.host_map:
        host_obj = scan_data.host_map[host_id]
        # Exclude ports that originated remotely that aren't part of the scope
        if len(host_obj.tags.intersection(set(tag_list))) == 0:
            return

        host_port_str = "%s:%s" % (host_obj.ipv4_addr, port_obj.port)

        host_port_entry = {'host_obj': host_obj, 'port_obj': port_obj}
        host_port_obj_map[host_port_str] = host_port_entry

        if host_id in scan_data.domain_host_id_map:
            domain_obj_list = scan_data.domain_host_id_map[host_id]
            for domain_obj in domain_obj_list:

                # Exclude domains that originated remotely that aren't part of the scope
                if len(domain_obj.tags.intersection(set(tag_list))) == 0:
                    continue

                domain_port_str = "%s:%s" % (
                    domain_obj.name, port_obj.port)

                host_port_entry = {
                    'host_obj': host_obj, 'port_obj': port_obj}
                host_port_obj_map[domain_port_str] = host_port_entry

    # else:
    #    logging.getLogger(__name__).debug("Host not found in map: %s" % host_id)


class CollectorType(enum.Enum):
    PASSIVE = 1
    ACTIVE = 2

    def __str__(self):
        if (self == CollectorType.PASSIVE):
            return "PASSIVE"
        elif (self == CollectorType.ACTIVE):
            return "ACTIVE"
        else:
            return None


class ToolExecutor():

    def __init__(self, thread_future_array=[], proc_pids=set()):
        self.thread_future_array = thread_future_array
        self.proc_pids = proc_pids

    def get_thread_futures(self):
        return self.thread_future_array

    def get_process_pids(self):
        return self.proc_pids


class RecordTag(enum.Enum):
    LOCAL = 1
    REMOTE = 2
    SCOPE = 3

    def __str__(self):
        if (self == RecordTag.LOCAL):
            return "LOCAL"
        elif (self == RecordTag.REMOTE):
            return "REMOTE"
        elif (self == RecordTag.SCOPE):
            return "SCOPE"
        else:
            return None


class WaluigiTool():

    def __init__(self):
        self.name = None
        self.collector_type = None
        self.scan_order = None
        self.args = None
        self.description = None
        self.project_url = None
        self.scope_func = None
        self.scan_func = None
        self.import_func = None

    def to_jsonable(self) -> dict:
        ret_dict = {}
        ret_dict['name'] = self.name
        ret_dict['tool_type'] = self.collector_type
        ret_dict['scan_order'] = self.scan_order
        ret_dict['args'] = self.args
        ret_dict['description'] = self.description
        ret_dict['project_url'] = self.project_url
        return ret_dict


class ImportToolXOutput(luigi.Task):

    def output(self):

        tool_output_file = self.input().path
        dir_path = os.path.dirname(tool_output_file)
        out_file = dir_path + os.path.sep + "tool_import_json"

        return luigi.LocalTarget(out_file)

    def complete(self):
        # Custom completion check: Verify the scan objects exist and update the scope
        output = self.output()
        if output.exists():

            import_arr = None
            with open(output.path, 'r') as import_fd:
                file_data = import_fd.read()
                import_arr = json.loads(file_data)

            # Update the scope
            if import_arr:
                scheduled_scan_obj = self.scan_input
                scheduled_scan_obj.scan_data.update(import_arr)

                return True

        return False

    def import_results(self, scheduled_scan_obj, obj_arr):

        scan_id = scheduled_scan_obj.scan_id
        recon_manager = scheduled_scan_obj.scan_thread.recon_manager
        tool_id = scheduled_scan_obj.current_tool.id

        if len(obj_arr) > 0:

            record_map = {}
            import_arr = []
            for obj in obj_arr:
                # Add record to map
                record_map[obj.id] = obj
                flat_obj = obj.to_jsonable()
                import_arr.append(flat_obj)

            # logging.getLogger(__name__).debug("Imported:\n %s" % str(import_arr))

            # Import the results to the server
            updated_record_map = recon_manager.import_data(
                scan_id, tool_id, import_arr)

            # logging.getLogger(__name__).debug("Returned map: %d" % len(updated_record_map))

            updated_import_arr = update_scope_array(
                record_map, updated_record_map)

            # logging.getLogger(__name__).debug("Updated scope")

            # Write imported data to file
            tool_import_file = self.output().path
            with open(tool_import_file, 'w') as import_fd:
                import_fd.write(json.dumps(updated_import_arr))

            # logging.getLogger(__name__).debug("Updating server")

            # Update the scan scope
            scheduled_scan_obj.scan_data.update(updated_import_arr)
        else:
            logging.getLogger(__name__).warning(
                "No objects to import for scan %s" % scan_id)


def update_scope_array(record_map, updated_record_map=None):

    # Update the record map with those from the database
    if updated_record_map and len(updated_record_map) > 0:
        id_updates = {}

        # Collect all updates
        for record_entry in updated_record_map:
            orig_id = record_entry['orig_id']
            db_id = record_entry['db_id']

            if orig_id in record_map and db_id != orig_id:
                record_obj = record_map[orig_id]
                record_obj.id = db_id

                id_updates[orig_id] = db_id
                record_map[db_id] = record_obj
                del record_map[orig_id]

        # Apply all updates in a single pass
        for record_obj in record_map.values():
            if record_obj.parent and record_obj.parent.id in id_updates:
                record_obj.parent.id = id_updates[record_obj.parent.id]

            if isinstance(record_obj, HttpEndpoint) and record_obj.web_path_id in id_updates:
                record_obj.web_path_id = id_updates[record_obj.web_path_id]

            if isinstance(record_obj, HttpEndpointData) and record_obj.domain_id in id_updates:
                record_obj.domain_id = id_updates[record_obj.domain_id]

    import_arr = []
    for obj_id in record_map:

        obj = record_map[obj_id]
        flat_obj = obj.to_jsonable()
        import_arr.append(flat_obj)

    return import_arr


class ScanData():

    def get_hosts(self, tag_list=None):

        host_list = []
        host_map = self.host_map
        for host_id in host_map:
            host_obj = host_map[host_id]

            if tag_list:
                if host_obj.tags.intersection(set(tag_list)):
                    host_list.append(host_obj)
            else:
                host_list.append(host_obj)

        return host_list

    def get_domains(self, tag_list=None):

        domain_name_list = []
        domain_map = self.domain_map
        for domain_id in domain_map:
            domain_obj = domain_map[domain_id]
            if tag_list:
                if domain_obj.tags.intersection(set(tag_list)) and domain_obj.name not in domain_name_list:
                    domain_name_list.append(domain_obj)
            elif domain_obj.name not in domain_name_list:
                domain_name_list.add(domain_obj)

        return domain_name_list

    def get_ports(self, tag_list=None):

        port_list = []
        port_map = self.port_map
        for port_id in port_map:
            port_obj = port_map[port_id]
            if tag_list:
                if port_obj.tags.intersection(set(tag_list)):
                    port_list.append(port_obj)
            else:
                port_list.append(port_obj)

        return port_list

    def get_scope_urls(self):

        endpoint_urls = set()
        http_endpoint_data_map = self.http_endpoint_data_map
        for http_endpoint_data_id in http_endpoint_data_map:
            http_endpoint_data_obj = http_endpoint_data_map[http_endpoint_data_id]
            if RecordTag.SCOPE.value in http_endpoint_data_obj.tags:
                url_str = http_endpoint_data_obj.get_url()
                if url_str:
                    endpoint_urls.add(url_str)

        return list(endpoint_urls)

    def update(self, record_map):

        # Parse the data
        import_list = []
        if isinstance(record_map, dict):
            import_list = list(record_map.values())
        else:
            import_list = record_map

        record_tags = set([RecordTag.LOCAL.value])
        self._process_data(import_list, record_tags)

        self._post_process()

    def _post_process(self):

        for port_id in self.port_map:
            update_host_port_obj_map(self, port_id, self.host_port_obj_map)

    def _process_data(self, obj_list, record_tags=set()):

        for obj in obj_list:
            if not isinstance(obj, Record):
                record_obj = Record.static_from_jsonsable(
                    input_dict=obj, scan_data=self, record_tags=record_tags)
                if record_obj is None:
                    continue
            else:
                record_obj = obj

            # logging.getLogger(__name__).warning(
            #    "Processing record of type %s" % type(record_obj))
            if isinstance(record_obj, Host):

                # Get IP as unique index for map
                host_ip = record_obj.ipv4_addr
                self.host_ip_id_map[host_ip] = record_obj.id

                # Add to the host insert list
                self.host_map[record_obj.id] = record_obj

            elif isinstance(record_obj, Domain):

                # Get host ID of port obj
                host_id = record_obj.parent.id
                if host_id in self.domain_host_id_map:
                    temp_domain_list = self.domain_host_id_map[host_id]
                else:
                    temp_domain_list = []
                    self.domain_host_id_map[host_id] = temp_domain_list

                # Add domain obj to list to be updated
                temp_domain_list.append(record_obj)

                # Create domain name id mapping
                domain_name = record_obj.name
                self.domain_name_map[domain_name] = record_obj

                # Add domain obj to list for being imported
                self.domain_map[record_obj.id] = record_obj

            elif isinstance(record_obj, Port):

                # Create host id to port list map
                host_id = record_obj.parent.id
                if host_id in self.host_id_port_map:
                    temp_port_list = self.host_id_port_map[host_id]
                else:
                    temp_port_list = []
                    self.host_id_port_map[host_id] = temp_port_list

                 # Add port obj to list to be updated
                temp_port_list.append(record_obj)

                # Create port number to host id map
                host_id = record_obj.parent.id
                port_str = record_obj.port
                if port_str in self.port_host_map:
                    temp_host_id_set = self.port_host_map[port_str]
                else:
                    temp_host_id_set = set()
                    self.port_host_map[port_str] = temp_host_id_set

                # Add port obj to list to be updated
                temp_host_id_set.add(host_id)

                # Add port obj to list for being imported
                self.port_map[record_obj.id] = record_obj

            elif isinstance(record_obj, ListItem):

                # Get path hash
                if record_obj.web_path_hash:
                    screenshot_path_hash = record_obj.web_path_hash.upper()
                    if screenshot_path_hash in self.path_hash_id_map:
                        temp_screenshot_list = self.path_hash_id_map[screenshot_path_hash]
                    else:
                        temp_screenshot_list = []
                        self.path_hash_id_map[screenshot_path_hash] = temp_screenshot_list

                    # Add port obj to list to be updated
                    temp_screenshot_list.append(record_obj.id)

                # Add path obj to list for being imported
                self.path_map[record_obj.id] = record_obj

            elif isinstance(record_obj, WebComponent):

                # Get port id
                port_id = record_obj.parent.id
                if port_id in self.component_port_id_map:
                    temp_list = self.component_port_id_map[port_id]
                else:
                    temp_list = []
                    self.component_port_id_map[port_id] = temp_list
                # Add port obj to list to be updated
                temp_list.append(record_obj)

                # Create a mapping of component name to port id
                component_key = record_obj.name
                if record_obj.version:
                    component_key += ":" + record_obj.version

                if component_key in self.component_name_port_id_map:
                    temp_list = self.component_name_port_id_map[component_key]
                else:
                    temp_list = []
                    self.component_name_port_id_map[component_key] = temp_list

                # Add port obj to list to be updated
                temp_list.append(port_id)

                # Add component obj to list for being imported
                self.component_map[record_obj.id] = record_obj

            elif isinstance(record_obj, Screenshot):

                # Get screenshot hash
                if record_obj.image_hash:
                    screenshot_path_hash = record_obj.image_hash.upper()
                    if screenshot_path_hash in self.screenshot_hash_id_map:
                        temp_screenshot_list = self.screenshot_hash_id_map[screenshot_path_hash]
                    else:
                        temp_screenshot_list = []
                        self.screenshot_hash_id_map[screenshot_path_hash] = temp_screenshot_list

                    # Add screenshot obj to list to be updated
                    temp_screenshot_list.append(record_obj.id)

                # Add screenshot obj to list for being imported
                self.screenshot_map[record_obj.id] = record_obj

            elif isinstance(record_obj, HttpEndpoint):

                # Get path id
                web_path_id = record_obj.web_path_id
                if web_path_id in self.http_endpoint_path_id_map:
                    temp_endpoint_list = self.http_endpoint_path_id_map[web_path_id]
                else:
                    temp_endpoint_list = []
                    self.http_endpoint_path_id_map[web_path_id] = temp_endpoint_list

                # Add path obj to list to be updated
                temp_endpoint_list.append(record_obj)

                # Get port id
                port_id = record_obj.parent.id
                if port_id in self.http_endpoint_port_id_map:
                    temp_endpoint_list = self.http_endpoint_port_id_map[port_id]
                else:
                    temp_endpoint_list = []
                    self.http_endpoint_port_id_map[port_id] = temp_endpoint_list

                # Add port obj to list to be updated
                temp_endpoint_list.append(record_obj)

                # Add http endpoint obj to list for being imported
                self.http_endpoint_map[record_obj.id] = record_obj

            elif isinstance(record_obj, HttpEndpointData):

                # Get http endpoint
                http_endpoint_id = record_obj.parent.id
                if http_endpoint_id in self.endpoint_data_endpoint_id_map:
                    temp_endpoint_list = self.endpoint_data_endpoint_id_map[http_endpoint_id]
                else:
                    temp_endpoint_list = []
                    self.endpoint_data_endpoint_id_map[http_endpoint_id] = temp_endpoint_list

                # Add path obj to list to be updated
                temp_endpoint_list.append(record_obj)

                # Get screenshot id
                screenshot_id = record_obj.screenshot_id
                if screenshot_id in self.http_endpoint_data_screenshot_id_map:
                    temp_endpoint_list = self.http_endpoint_data_screenshot_id_map[screenshot_id]
                else:
                    temp_endpoint_list = []
                    self.http_endpoint_data_screenshot_id_map[screenshot_id] = temp_endpoint_list

                # Add screenshot obj to list to be updated
                temp_endpoint_list.append(record_obj)

                # Add http endpoint obj to list for being imported
                self.http_endpoint_data_map[record_obj.id] = record_obj

            elif isinstance(record_obj, Vuln):

                # Get vuln name
                vuln_name = record_obj.name
                if vuln_name in self.vulnerability_name_id_map:
                    temp_vuln_list = self.vulnerability_name_id_map[vuln_name]
                else:
                    temp_vuln_list = []
                    self.vulnerability_name_id_map[vuln_name] = temp_vuln_list

                # Add vuln obj to list
                temp_vuln_list.append(record_obj)

                # Add vulnerability obj to list for being imported
                self.vulnerability_map[record_obj.id] = record_obj

            elif isinstance(record_obj, CollectionModule):

                # Get module name
                module_name = record_obj.name
                if module_name in self.module_name_id_map:
                    temp_module_list = self.module_name_id_map[module_name]
                else:
                    temp_module_list = []
                    self.module_name_id_map[module_name] = temp_module_list

                # Add module obj to list
                temp_module_list.append(record_obj)

                # Add collection module obj to list for being imported
                self.collection_module_map[record_obj.id] = record_obj

            elif isinstance(record_obj, CollectionModuleOutput):

                # Get module id
                module_id = record_obj.parent.id
                if module_id in self.module_output_module_id_map:
                    temp_module_ouput_list = self.module_output_module_id_map[module_id]
                else:
                    temp_module_ouput_list = []
                    self.module_output_module_id_map[module_id] = temp_module_ouput_list

                # Add module obj to list
                temp_module_ouput_list.append(record_obj)

                port_id = record_obj.port_id
                if port_id in self.collection_module_output_port_id_map:
                    temp_module_ouput_list = self.collection_module_output_port_id_map[port_id]
                else:
                    temp_module_ouput_list = []
                    self.collection_module_output_port_id_map[port_id] = temp_module_ouput_list

                # Add module obj to list
                temp_module_ouput_list.append(record_obj)

                # Add collection module output obj to list for being imported
                self.collection_module_output_map[record_obj.id] = record_obj

            elif isinstance(record_obj, Certificate):

                # Get port id
                port_id = record_obj.parent.id
                if port_id in self.certificate_port_id_map:
                    temp_endpoint_list = self.certificate_port_id_map[port_id]
                else:
                    temp_endpoint_list = []
                    self.certificate_port_id_map[port_id] = temp_endpoint_list

                # Add port obj to list to be updated
                temp_endpoint_list.append(record_obj)

                # Add certificate obj to list for being imported
                self.certificate_map[record_obj.id] = record_obj

            elif isinstance(record_obj, Subnet):

                # Add screenshot obj to list for being imported
                self.subnet_map[record_obj.id] = record_obj

            # Add to overall map
            self.scan_obj_map[record_obj.id] = record_obj

    def get_port_number_list_from_scope(self):
        return list(self.port_number_list)

    def get_port_number_list_from_port_map(self):
        port_number_list = set()
        for port_id in self.port_map:
            port_obj = self.port_map[port_id]
            if port_obj.port:
                port_number_list.add(str(port_obj.port))
        return list(port_number_list)

    def __init__(self, scan_data, record_tags=set()):

        self.scan_obj_list = []
        self.module_id = None

        # Maps object IDs to the obj
        self.scan_obj_map = {}

        self.subnet_map = {}

        self.host_map = {}
        self.host_ip_id_map = {}

        # Maps ip:port/domain:port to a host and port object tuple
        self.host_port_obj_map = {}

        # Maps domain names to domain ids
        self.domain_name_map = {}

        self.domain_map = {}
        self.domain_host_id_map = {}

        # Maps domain:port to to host id port id tuple
        self.domain_port_id_map = {}

        self.port_map = {}
        self.port_host_map = {}
        self.host_id_port_map = {}

        self.component_map = {}
        self.component_port_id_map = {}
        self.component_name_port_id_map = {}

        self.module_name_component_map = {}

        self.path_map = {}
        self.path_hash_id_map = {}

        self.screenshot_map = {}
        self.screenshot_hash_id_map = {}

        self.http_endpoint_map = {}
        self.http_endpoint_port_id_map = {}
        self.http_endpoint_path_id_map = {}
        self.http_endpoint_data_screenshot_id_map = {}

        self.http_endpoint_data_map = {}
        self.endpoint_data_endpoint_id_map = {}

        self.collection_module_map = {}
        self.module_name_id_map = {}

        self.collection_module_output_map = {}
        self.collection_module_output_port_id_map = {}
        self.module_output_module_id_map = {}

        self.vulnerability_map = {}
        self.vulnerability_name_id_map = {}

        self.certificate_map = {}
        self.certificate_port_id_map = {}

        self.port_number_list = []

        self.host_count = 0

        self.module_map = {}
        self.component_name_module_map = {}

        # logging.getLogger(__name__).debug("Processing scan data\n %s" % scan_data)
        # Decode the port map
        if 'b64_port_bitmap' in scan_data and scan_data['b64_port_bitmap']:
            b64_port_bitmap = scan_data['b64_port_bitmap']
            if len(b64_port_bitmap) > 0:
                port_map = base64.b64decode(b64_port_bitmap)
                self.port_number_list = scan_utils.get_ports(port_map)

        if 'obj_list' in scan_data and scan_data['obj_list']:
            obj_list = scan_data['obj_list']

            # Parse the data
            self._process_data(obj_list, record_tags=record_tags)

        # Post process
        self._post_process()


class Record():

    def __init__(self, id=None, parent=None, collection_tool_instance_id=None):
        self.id = id if id is not None else format(
            uuid.uuid4().int, 'x')
        self.parent = parent
        self.scan_data = None
        self.tags = set()
        self.collection_tool_instance_id = collection_tool_instance_id

    def _data_to_jsonable(self):
        return None

    def to_jsonable(self):

        parent_dict = None
        if self.parent:
            parent_dict = {'type': str(
                self.parent.__class__.__name__).lower(), 'id': self.parent.id}

        ret = {}
        ret['id'] = self.id
        ret['type'] = str(self.__class__.__name__).lower()
        ret['parent'] = parent_dict
        ret['collection_tool_instance_id'] = self.collection_tool_instance_id

        ret['data'] = self._data_to_jsonable()

        return ret

    def from_jsonsable(self, input_data_dict):
        logging.getLogger(__name__).error(
            f"from_jsonsable called on type: {type(self)}")
        raise Exception('No jsonable method defined for the child object.')

    @staticmethod
    def static_from_jsonsable(input_dict, scan_data=None, record_tags=set()):
        obj = None
        record_tags_inst = set(record_tags)

        obj_id = input_dict['id']

        record_data = input_dict['data']
        parent_id = None
        if 'parent' in input_dict:
            parent_record = input_dict['parent']
            if parent_record:
                parent_id = parent_record['id']

        if 'tags' in input_dict:
            record_tags_set = input_dict['tags']
            record_tags_inst.update(record_tags_set)

        # Create record
        try:
            record_type = input_dict['type']
            if record_type == 'host':
                obj = Host(id=obj_id)
            elif record_type == 'port':
                obj = Port(id=obj_id, parent_id=parent_id)
            elif record_type == 'domain':
                obj = Domain(id=obj_id, parent_id=parent_id)
            elif record_type == 'listitem':
                obj = ListItem(id=obj_id)
            elif record_type == 'httpendpoint':
                obj = HttpEndpoint(id=obj_id, parent_id=parent_id)
            elif record_type == 'httpendpointdata':
                obj = HttpEndpointData(
                    id=obj_id, parent_id=parent_id)
            elif record_type == 'screenshot':
                obj = Screenshot(id=obj_id)
            elif record_type == 'webcomponent':
                obj = WebComponent(id=obj_id, parent_id=parent_id)
            elif record_type == 'vuln':
                obj = Vuln(id=obj_id, parent_id=parent_id)
            elif record_type == 'collectionmodule':
                obj = CollectionModule(
                    id=obj_id, parent_id=parent_id)
            elif record_type == 'collectionmoduleoutput':
                obj = CollectionModuleOutput(id=obj_id, parent_id=parent_id)
            elif record_type == 'certificate':
                obj = Certificate(id=obj_id, parent_id=parent_id)
            elif record_type == 'subnet':
                obj = Subnet(id=obj_id)
            else:
                logging.getLogger(__name__).debug(
                    "Unknown record type: %s" % record_type)
                return

            # Populate data
            if obj:
                if 'collection_tool_instance_id' in input_dict:
                    obj.collection_tool_instance_id = input_dict['collection_tool_instance_id']
                else:
                    logging.getLogger(__name__).warning(
                        "No collection tool instance ID found for record type: %s" % record_type)

                obj.scan_data = scan_data
                obj.tags.update(record_tags_inst)
                obj.from_jsonsable(record_data)

        except Exception as e:
            logging.getLogger(__name__).error(traceback.format_exc())
            raise Exception('Invalid scan object: %s' % str(e))

        return obj


class Tool(Record):

    def __init__(self, tool_id):
        super().__init__(id=tool_id)


class Subnet(Record):

    def __init__(self,  id=None):
        super().__init__(id=id, parent=None)

        self.subnet = None
        self.mask = None

    def from_jsonsable(self, input_data_dict):
        try:
            self.subnet = input_data_dict['subnet']
            self.mask = input_data_dict['mask']
        except Exception as e:
            raise Exception('Invalid subnet object: %s' % str(e))


class Host(Record):

    def __init__(self,  id=None):
        super().__init__(id=id, parent=None)

        self.ipv4_addr = None
        self.ipv6_addr = None

    def _data_to_jsonable(self):
        ret = {}
        if self.ipv4_addr:
            ret['ipv4_addr'] = self.ipv4_addr
        elif self.ipv6_addr:
            ret['ipv6_addr'] = self.ipv6_addr
        return ret

    def from_jsonsable(self, input_data_dict):
        try:
            if 'ipv4_addr' in input_data_dict:
                ipv4_addr_str = input_data_dict['ipv4_addr']
                self.ipv4_addr = str(netaddr.IPAddress(ipv4_addr_str))
            # elif 'ipv6_addr' in input_data_dict:
            #     ipv6_addr_str = input_data_dict['ipv6_addr']
            #     self.ipv6_addr = int(netaddr.IPAddress(input_data_dict['ipv6_addr_str']))
        except Exception as e:
            raise Exception('Invalid host object: %s' % str(e))


class Port(Record):

    def __init__(self,  parent_id=None, id=None):
        super().__init__(id=id, parent=Host(id=parent_id))

        self.proto = None
        self.port = None
        self.secure = False

    def _data_to_jsonable(self):
        ret = {'port': self.port, 'proto': self.proto}
        if self.secure is not None:
            ret['secure'] = self.secure
        return ret

    def from_jsonsable(self, input_data_dict):
        try:
            self.port = str(input_data_dict['port'])
            self.proto = int(input_data_dict['proto'])
            if 'secure' in input_data_dict:
                secure_int = input_data_dict['secure']
                if secure_int == 1:
                    self.secure = True
                else:
                    self.secure = False

        except Exception as e:
            raise Exception('Invalid port object: %s' % str(e))


class Domain(Record):

    def __init__(self,  parent_id=None, id=None):
        super().__init__(id=id, parent=Host(id=parent_id))

        self.name = None

    def _data_to_jsonable(self):
        return {'name': self.name}

    def from_jsonsable(self, input_data_dict):
        try:
            self.name = input_data_dict['name']
        except Exception as e:
            raise Exception('Invalid domain object: %s' % str(e))


class WebComponent(Record):

    def __init__(self,  parent_id=None, id=None):
        super().__init__(id=id, parent=Port(id=parent_id))

        self.name = None
        self.version = None

    def _data_to_jsonable(self):
        ret = {'name': self.name}
        if self.version is not None:
            ret['version'] = self.version
        return ret

    def from_jsonsable(self, input_data_dict):
        try:
            self.name = input_data_dict['name']
            if 'version' in input_data_dict:
                self.version = input_data_dict['version']
        except Exception as e:
            raise Exception('Invalid component object: %s' % str(e))


class Vuln(Record):

    def __init__(self,  parent_id=None, id=None):
        super().__init__(id=id, parent=Port(id=parent_id))

        self.name = None
        self.vuln_details = None
        self.endpoint_id = None

    def _data_to_jsonable(self):
        ret = {'name': self.name}
        if self.vuln_details:
            ret['vuln_details'] = self.vuln_details
        if self.endpoint_id:
            ret['endpoint_id'] = self.endpoint_id
        return ret

    def from_jsonsable(self, input_data_dict):
        try:
            self.name = input_data_dict['name']
            if 'vuln_details' in input_data_dict:
                self.vuln_details = input_data_dict['vuln_details']
            if 'endpoint_id' in input_data_dict:
                self.endpoint_id = input_data_dict['endpoint_id']
        except Exception as e:
            raise Exception('Invalid vuln object: %s' % str(e))


class ListItem(Record):

    def __init__(self,  id=None):
        super().__init__(id=id)

        self.web_path = None
        self.web_path_hash = None

    def _data_to_jsonable(self):
        return {'path': self.web_path,
                'path_hash': self.web_path_hash}

    def from_jsonsable(self, input_data_dict):
        try:
            self.web_path = input_data_dict['path']
            self.web_path_hash = input_data_dict['path_hash']
        except Exception as e:
            raise Exception('Invalid path object: %s' % str(e))

        if self.web_path is None:
            self.web_path = '/'
            hashobj = hashlib.sha1()
            hashobj.update(self.web_path.encode())
            path_hash = hashobj.digest()
            hex_str = binascii.hexlify(path_hash).decode()
            self.web_path_hash = hex_str


class Screenshot(Record):

    def __init__(self,  id=None):
        super().__init__(id=id)

        self.screenshot = None
        self.image_hash = None

    def _data_to_jsonable(self):
        return {'screenshot': self.screenshot,
                'image_hash': self.image_hash}

    def from_jsonsable(self, input_data_dict):
        try:

            if 'screenshot' in input_data_dict:
                self.screenshot = input_data_dict['screenshot']

            if 'image_hash' in input_data_dict:
                self.image_hash = input_data_dict['image_hash']

        except Exception as e:
            raise Exception('Invalid screenshot object: %s' % str(e))


class HttpEndpoint(Record):

    def __init__(self,  parent_id=None, id=None):
        super().__init__(id=id, parent=Port(id=parent_id))
        self.web_path_id = None

    def get_port(self):
        port_str = ''
        port_id = self.parent.id
        if port_id in self.scan_data.port_map:
            port_obj = self.scan_data.port_map[port_id]
            return port_obj.port
        return port_str

    def get_url(self):
        port_id = self.parent.id
        host_ip = None
        port_str = None
        secure = None
        query_str = None

        if port_id in self.scan_data.port_map:
            port_obj = self.scan_data.port_map[port_id]
            port_str = port_obj.port
            secure = port_obj.secure

            if port_obj.parent.id in self.scan_data.host_map:
                host_obj = self.scan_data.host_map[port_obj.parent.id]
                if host_obj:
                    host_ip = host_obj.ipv4_addr

        if self.id in self.scan_data.http_endpoint_map:
            http_endpoint_data_obj_list = self.scan_data.endpoint_data_endpoint_id_map[
                self.id]
            for http_endpoint_data_obj in http_endpoint_data_obj_list:
                if http_endpoint_data_obj.domain_id and http_endpoint_data_obj.domain_id in self.scan_data.domain_map:
                    domain_obj = self.scan_data.domain_map[http_endpoint_data_obj.domain_id]
                    if domain_obj:
                        host_ip = domain_obj.name
                        break

        if self.web_path_id in self.scan_data.path_map:
            path_obj = self.scan_data.path_map[self.web_path_id]
            query_str = path_obj.web_path

        url_str = scan_utils.construct_url(
            host_ip, port_str, secure, query_str)

        return url_str

    def _data_to_jsonable(self):

        ret = {'web_path_id': self.web_path_id}

        return ret

    def from_jsonsable(self, input_data_dict):
        try:

            if 'web_path_id' in input_data_dict:
                self.web_path_id = input_data_dict['web_path_id']

        except Exception as e:
            raise Exception('Invalid http endpoint object: %s' % str(e))


class HttpEndpointData(Record):

    def __init__(self,  parent_id=None, id=None):
        super().__init__(id=id, parent=HttpEndpoint(id=parent_id))

        self.title = None
        self.status = None
        self.domain_id = None
        self.screenshot_id = None
        self.last_modified = None
        self.fav_icon_hash = None

    def _data_to_jsonable(self):
        ret = {'title': self.title, 'status': self.status}

        if self.last_modified is not None:
            ret['last_modified'] = self.last_modified

        if self.domain_id is not None:
            ret['domain_id'] = self.domain_id

        if self.screenshot_id is not None:
            ret['screenshot_id'] = self.screenshot_id

        if self.fav_icon_hash is not None:
            ret['fav_icon_hash'] = self.fav_icon_hash

        return ret

    def get_url(self):

        port_id = None
        host_ip = None
        port_str = None
        secure = None
        query_str = None

        if self.parent.id in self.scan_data.http_endpoint_map:
            http_endpoint_obj = self.scan_data.http_endpoint_map[self.parent.id]
            port_id = http_endpoint_obj.parent.id
            web_path_id = http_endpoint_obj.web_path_id

            if web_path_id in self.scan_data.path_map:
                path_obj = self.scan_data.path_map[web_path_id]
                query_str = path_obj.web_path

        if port_id and port_id in self.scan_data.port_map:
            port_obj = self.scan_data.port_map[port_id]
            port_str = port_obj.port
            secure = port_obj.secure

            if port_obj.parent.id in self.scan_data.host_map:
                host_obj = self.scan_data.host_map[port_obj.parent.id]
                if host_obj:
                    host_ip = host_obj.ipv4_addr

        if self.domain_id and self.domain_id in self.scan_data.domain_map:
            domain_obj = self.scan_data.domain_map[self.domain_id]
            if domain_obj:
                host_ip = domain_obj.name

        url_str = scan_utils.construct_url(
            host_ip, port_str, secure, query_str)

        return url_str

    def from_jsonsable(self, input_data_dict):
        try:

            self.screenshot_id = None
            self.last_modified = None
            self.domain_id = None
            self.fav_icon_hash = None

            if 'title' in input_data_dict:
                self.title = input_data_dict['title']

            if 'status' in input_data_dict:
                self.status = input_data_dict['status']

            if 'last_modified' in input_data_dict:
                self.last_modified = input_data_dict['last_modified']

            if 'screenshot_id' in input_data_dict:
                self.screenshot_id = input_data_dict['screenshot_id']

            if 'domain_id' in input_data_dict:
                self.domain_id = input_data_dict['domain_id']

            if 'fav_icon_hash' in input_data_dict and input_data_dict['fav_icon_hash']:
                self.fav_icon_hash = input_data_dict['fav_icon_hash']

        except Exception as e:
            raise Exception('Invalid http endpoint data object: %s' % str(e))


class CollectionModule(Record):

    def __init__(self,  parent_id=None, id=None):
        super().__init__(id=id, parent=Tool(parent_id))

        self.name = None
        self.args = None
        self.bindings = None
        self.outputs = None

    def _data_to_jsonable(self):
        ret = {'name': self.name, 'args': self.args}
        return ret

    def get_output_components(self):
        output_components = []

        component_arr = self.outputs
        if component_arr is None:
            return output_components

        component_map = self.scan_data.component_map
        for component_id in component_arr:
            if component_id in component_map:
                component_obj = component_map[component_id]
                output_components.append(component_obj)

        return output_components

    def get_host_port_obj_map(self):
        host_port_obj_map = {}

        component_arr = self.bindings
        if component_arr is None:
            return host_port_obj_map

        component_map = self.scan_data.component_map
        component_name_port_id_map = self.scan_data.component_name_port_id_map

        # Get the module binding and see if there are any ports mapped to this component name
        for component_id in component_arr:
            if component_id in component_map:

                component_obj = component_map[component_id]
                component_key = component_obj.name

                if component_key in component_name_port_id_map:
                    port_id_list = component_name_port_id_map[component_key]
                    for port_id in port_id_list:
                        if port_id in self.scan_data.port_map:
                            update_host_port_obj_map(
                                self.scan_data, port_id, host_port_obj_map)
                else:
                    logging.getLogger(__name__).debug(
                        "Component key not found in component name port id map: %s" % component_key)
            else:
                logging.getLogger(__name__).debug(
                    "Component id not found in component map: %s" % component_id)

        return host_port_obj_map

    def from_jsonsable(self, input_data_dict):
        try:

            self.name = str(input_data_dict['name'])
            self.args = str(input_data_dict['args'])

            if 'bindings' in input_data_dict:
                self.bindings = input_data_dict['bindings']
            if 'outputs' in input_data_dict:
                self.outputs = input_data_dict['outputs']

        except Exception as e:
            raise Exception('Invalid collection module object: %s' % str(e))


class CollectionModuleOutput(Record):

    def __init__(self,  parent_id=None, id=None):
        super().__init__(id=id, parent=CollectionModule(id=parent_id))

        self.data = None
        self.port_id = None

    def _data_to_jsonable(self):
        ret = {'output': self.data, 'port_id': self.port_id}
        return ret

    def from_jsonsable(self, input_data_dict):
        try:

            self.data = str(input_data_dict['output'])
            self.port_id = str(input_data_dict['port_id'])

        except Exception as e:
            raise Exception(
                'Invalid collection module output object: %s' % str(e))


class Certificate(Record):

    def __init__(self,  parent_id=None, id=None):
        super().__init__(id=id, parent=Port(id=parent_id))

        self.issuer = None
        self.issued = None
        self.expires = None
        self.fingerprint_hash = None
        self.domain_name_id_map = {}
        self.domain_id_list = []

    def _data_to_jsonable(self):
        ret = {'issuer': self.issuer}
        ret['issued'] = self.issued
        ret['expires'] = self.expires
        ret['fingerprint_hash'] = self.fingerprint_hash
        ret['domain_id_list'] = list(self.domain_name_id_map.values())
        return ret

    def from_jsonsable(self, input_data_dict):
        try:
            self.issuer = input_data_dict['issuer']
            self.issued = int(input_data_dict['issued'])
            self.expires = int(input_data_dict['expires'])
            self.fingerprint_hash = input_data_dict['fingerprint_hash']
            self.domain_id_list = input_data_dict['domain_id_list']

        except Exception as e:
            raise Exception('Invalid module output object: %s' % str(e))

    def add_domain(self, host_id, domain_str, collection_tool_instance_id):

        # If it's a wildcard
        if "*." in domain_str:
            return None

        # If it's an IP skip it
        try:
            int(netaddr.IPAddress(domain_str))
            return None
        except:
            pass

        if domain_str not in self.domain_name_id_map:
            domain_obj = Domain(parent_id=host_id)
            domain_obj.collection_tool_instance_id = collection_tool_instance_id
            domain_obj.name = domain_str

            self.domain_name_id_map[domain_str] = domain_obj.id
            return domain_obj
