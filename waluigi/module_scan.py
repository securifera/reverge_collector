from waluigi import data_model
from types import SimpleNamespace
from waluigi import nmap_scan
from waluigi import nuclei_scan
from waluigi.recon_manager import ScheduledScan

import logging
import copy

logger = logging.getLogger(__name__)


class Module(data_model.WaluigiTool):

    def __init__(self):
        self.name = 'module'
        self.description = "The module tool is used to run nmap and nuclei modules based on associated mappings in reverge"
        self.project_url = "https://github.com/securifera/reverge_collector"
        self.collector_type = data_model.CollectorType.ACTIVE.value
        self.scan_order = 9
        self.args = ""
        self.scan_func = Module.module_scan_func
        self.import_func = Module.module_import

    @staticmethod
    def module_scan_func(scheduled_scan_obj: ScheduledScan):

        ret_val = True

        # Get scope
        module_tool = scheduled_scan_obj.current_tool
        scope_obj = scheduled_scan_obj.scan_data

        collection_module_map = scope_obj.collection_module_map
        module_arr = list(collection_module_map.values())

        for module_scan_inst in module_arr:

            tool_args = module_scan_inst.args
            host_port_obj_map = module_scan_inst.get_host_port_obj_map()
            if len(host_port_obj_map) == 0:
                continue

            scope_copy = copy.deepcopy(scope_obj)
            scope_copy.host_port_obj_map = host_port_obj_map
            scheduled_scan_obj.scan_data = scope_copy

            # Get/Set the module id
            module_id = module_scan_inst.id
            scope_copy.module_id = module_id

            tool_id = module_scan_inst.parent.id
            tool_map = scheduled_scan_obj.scan_thread.recon_manager.get_tool_map()
            if tool_id in tool_map:
                tool_inst = tool_map[tool_id]

                tool_name = tool_inst.name
                tool_obj = SimpleNamespace(
                    id=tool_id, name=tool_name, args=tool_args)
                scheduled_scan_obj.current_tool = tool_obj

                # Set scan input
                if tool_name == 'nmap':

                    # Execute nmap
                    ret = nmap_scan.Nmap.nmap_scan_func(scheduled_scan_obj)

                elif tool_name == 'nuclei':

                    # Execute nuclei
                    ret = nuclei_scan.Nuclei.nuclei_scan_func(
                        scheduled_scan_obj)

                if not ret:
                    logger.error("[-] Module Scan Failed")
                    ret_val = False

                # Reset values
                scheduled_scan_obj.current_tool = module_tool

            else:
                logger.error("Tool id not found %s" % tool_id)

        # Restore scope object
        scheduled_scan_obj.scan_data = scope_obj
        return ret_val

    @staticmethod
    def module_import(scheduled_scan_obj: ScheduledScan):

        ret_val = True

        scope_obj = scheduled_scan_obj.scan_data

        collection_module_map = scope_obj.collection_module_map
        module_arr = list(collection_module_map.values())

        # Get scope
        module_tool = scheduled_scan_obj.current_tool
        for module_scan_inst in module_arr:

            scope_copy = copy.deepcopy(scope_obj)
            scheduled_scan_obj.scan_data = scope_copy

            # Get/Set the module id
            module_id = module_scan_inst.id
            scope_copy.module_id = module_id
            scope_copy.module_outputs = module_scan_inst.get_output_components()

            tool_id = module_scan_inst.parent.id
            tool_map = scheduled_scan_obj.scan_thread.recon_manager.get_tool_map()

            if tool_id in tool_map:
                tool_inst = tool_map[tool_id]

                tool_name = tool_inst.name
                tool_obj = SimpleNamespace(
                    id=tool_id, name=tool_name)
                scheduled_scan_obj.current_tool = tool_obj

                # tool_name = tool_obj.name
                logger.debug("Tool name: %s" % tool_name)

                ret = None
                scheduled_scan_obj.current_tool = tool_obj
                if tool_name == 'nmap':

                    # Execute nmap
                    ret = nmap_scan.Nmap.nmap_import(scheduled_scan_obj)

                elif tool_name == 'nuclei':

                    # Execute nuclei
                    ret = nuclei_scan.Nuclei.nuclei_import(scheduled_scan_obj)

                if not ret:
                    logger.error("Module Import Failed")
                    ret_val = False

                # Reset values
                scheduled_scan_obj.current_tool = module_tool

        # Restore scope object
        scheduled_scan_obj.scan_data = scope_obj

        return ret_val
