"""
Module Scan Framework.

This module provides dynamic scanning module execution for the Waluigi framework,
enabling the automated execution of specialized scanning modules (like Nmap and Nuclei)
based on associated mappings configured in the Reverge platform. It acts as a meta-tool
that orchestrates the execution of other scanning tools with customized parameters.

The module supports:
    - Dynamic module loading and execution based on configuration
    - Automatic tool selection and parameter passing
    - Module-specific target scoping and parameter customization
    - Integrated execution of Nmap and Nuclei scanning modules
    - Result import and processing for discovered module outputs
    - Deep copy isolation for module execution environments

Classes:
    Module: Main module execution tool implementing dynamic scanning workflows

Functions:
    module_scan_func: Static method for executing configured scanning modules
    module_import: Static method for importing module execution results

Example:
    Module execution through the Waluigi framework::
    
        # Initialize the module tool
        module_tool = Module()
        
        # Execute configured modules (automatically determined)
        success = module_tool.scan_func(scheduled_scan_obj)
        
        # Import module results
        success = module_tool.import_func(scheduled_scan_obj)

Note:
    This module requires proper module configuration in the scan data's
    collection_module_map. It dynamically executes Nmap and Nuclei modules
    based on the configured mappings and parameters.

.. moduleauthor:: Waluigi Framework Team
.. version:: 1.0.0
"""

from waluigi import data_model
from types import SimpleNamespace
from waluigi import nmap_scan
from waluigi import nuclei_scan
from waluigi.data_model import ScheduledScan
from typing import Dict, List, Any, Optional

import logging
import copy


class Module(data_model.WaluigiTool):
    """
    Dynamic scanning module execution tool for the Waluigi framework.

    This class provides a meta-tool capability that dynamically executes other
    scanning tools (Nmap, Nuclei) based on module configurations stored in the
    scan data. It enables customized scanning workflows where different modules
    are executed with specific parameters and target scopes.

    The Module tool operates by:
        - Reading module configurations from the scan data
        - Creating isolated execution environments for each module
        - Dynamically selecting and executing the appropriate scanning tool
        - Managing tool instance states and parameter passing
        - Coordinating result import and processing workflows

    Attributes:
        name (str): The tool identifier ('module')
        description (str): Human-readable description of module functionality
        project_url (str): URL to the project repository
        collector_type (int): Identifies this as an active scanning tool
        scan_order (int): Execution priority within the reconnaissance workflow (9)
        args (str): Command-line arguments (empty for meta-tools)
        scan_func (callable): Static method for module execution
        import_func (callable): Static method for result import

    Methods:
        module_scan_func: Execute all configured scanning modules
        module_import: Import results from executed modules

    Example:
        >>> module_tool = Module()
        >>> print(module_tool.name)
        module

        >>> # Execute through framework (requires module configuration)
        >>> success = module_tool.scan_func(scheduled_scan_obj)
        >>> if success:
        ...     print("All modules executed successfully")

    Note:
        The scan_order of 9 positions this tool late in the reconnaissance
        workflow, after initial discovery and enumeration phases. Requires
        proper module configuration in the scan data structure.
    """

    def __init__(self) -> None:
        """
        Initialize the Module tool with default configuration.

        Sets up the meta-tool with appropriate parameters for dynamic module
        execution, including workflow positioning and execution method bindings.
        """
        self.name = 'module'
        self.description = "The module tool is used to run nmap and nuclei modules based on associated mappings in reverge"
        self.project_url = "https://github.com/securifera/reverge_collector"
        self.collector_type = data_model.CollectorType.ACTIVE.value
        self.scan_order = 9
        self.args = ""
        self.scan_func = Module.module_scan_func
        self.import_func = Module.module_import

    @staticmethod
    def module_scan_func(scheduled_scan_obj: ScheduledScan) -> bool:
        """
        Execute all configured scanning modules with their specific parameters.

        This method iterates through all configured scanning modules in the scan
        data, creates isolated execution environments for each module, and executes
        the appropriate scanning tool (Nmap or Nuclei) with module-specific
        parameters and target scopes.

        The execution process includes:
            - Extracting module configurations from scan data
            - Creating deep copy isolation for each module execution
            - Setting up module-specific target scopes and parameters
            - Dynamically selecting and executing the appropriate tool
            - Managing tool instance states during execution
            - Coordinating error handling and result validation

        Args:
            scheduled_scan_obj (ScheduledScan): The scheduled scan object containing
                module configurations, target data, and execution context.

        Returns:
            bool: True if all configured modules executed successfully,
                  False if any module execution failed.

        Example:
            >>> success = Module.module_scan_func(scheduled_scan_obj)
            >>> if success:
            ...     print("All modules completed successfully")

        Note:
            Each module executes in an isolated environment with its own
            target scope and parameters. The original scan data is restored
            after all modules complete execution.
        """

        ret_val = True

        # Extract module tool and scan data
        module_tool = scheduled_scan_obj.current_tool
        scope_obj = scheduled_scan_obj.scan_data

        # Get configured modules from scan data
        collection_module_map = scope_obj.collection_module_map
        module_arr = list(collection_module_map.values())

        # Execute each configured module
        for module_scan_inst in module_arr:
            tool_args = module_scan_inst.args
            host_port_obj_map = module_scan_inst.get_host_port_obj_map()

            # Skip modules with no targets
            if len(host_port_obj_map) == 0:
                continue

            # Create isolated execution environment
            scope_copy = copy.deepcopy(scope_obj)
            scope_copy.host_port_obj_map = host_port_obj_map
            scheduled_scan_obj.scan_data = scope_copy

            # Configure module-specific parameters
            module_id = module_scan_inst.id
            scope_copy.module_id = module_id

            # Resolve tool configuration
            tool_id = module_scan_inst.parent.id
            tool_map = scheduled_scan_obj.scan_thread.recon_manager.get_tool_map()

            if tool_id in tool_map:
                tool_inst = tool_map[tool_id]
                tool_name = tool_inst.name

                # Create tool object for execution
                tool_obj = SimpleNamespace(
                    id=tool_id, name=tool_name, args=tool_args)
                scheduled_scan_obj.current_tool = tool_obj

                # Execute appropriate scanning tool
                ret = False
                if tool_name == 'nmap':
                    ret = nmap_scan.Nmap.nmap_scan_func(scheduled_scan_obj)
                elif tool_name == 'nuclei':
                    ret = nuclei_scan.Nuclei.nuclei_scan_func(
                        scheduled_scan_obj)

                # Handle execution results
                if not ret:
                    logging.getLogger(__name__).error("[-] Module Scan Failed")
                    ret_val = False

                # Restore original tool reference
                scheduled_scan_obj.current_tool = module_tool
            else:
                logging.getLogger(__name__).error(
                    f"Tool id not found {tool_id}")

        # Restore original scan data
        scheduled_scan_obj.scan_data = scope_obj
        return ret_val

    @staticmethod
    def module_import(scheduled_scan_obj: ScheduledScan) -> bool:
        """
        Import and process results from executed scanning modules.

        This method handles the import and integration of results from all
        executed scanning modules. It creates isolated environments for each
        module's result processing and delegates to the appropriate tool's
        import functionality.

        The import process includes:
            - Extracting module configurations and output components
            - Creating isolated processing environments for each module
            - Setting up module-specific result processing contexts
            - Delegating to appropriate tool import methods
            - Managing tool instance states during import
            - Coordinating error handling and validation

        Args:
            scheduled_scan_obj (ScheduledScan): The scheduled scan object containing
                module configurations, output data, and processing context.

        Returns:
            bool: True if all module results were imported successfully,
                  False if any import operation failed.

        Example:
            >>> success = Module.module_import(scheduled_scan_obj)
            >>> if success:
            ...     print("All module results imported successfully")

        Note:
            Each module's results are processed in isolation with their own
            output components and processing context. The original scan data
            is restored after all imports complete.
        """

        ret_val = True

        # Extract scan data and module tool reference
        scope_obj = scheduled_scan_obj.scan_data
        module_tool = scheduled_scan_obj.current_tool

        # Get configured modules from scan data
        collection_module_map = scope_obj.collection_module_map
        module_arr = list(collection_module_map.values())

        # Process results for each configured module
        for module_scan_inst in module_arr:
            # Create isolated processing environment
            scope_copy = copy.deepcopy(scope_obj)
            scheduled_scan_obj.scan_data = scope_copy

            # Configure module-specific processing context
            module_id = module_scan_inst.id
            scope_copy.module_id = module_id
            scope_copy.module_outputs = module_scan_inst.get_output_components()

            # Resolve tool configuration for import
            tool_id = module_scan_inst.parent.id
            tool_map = scheduled_scan_obj.scan_thread.recon_manager.get_tool_map()

            if tool_id in tool_map:
                tool_inst = tool_map[tool_id]
                tool_name = tool_inst.name

                # Create tool object for import processing
                tool_obj = SimpleNamespace(id=tool_id, name=tool_name)
                scheduled_scan_obj.current_tool = tool_obj

                logging.getLogger(__name__).debug(f"Tool name: {tool_name}")

                # Delegate to appropriate tool import method
                ret = None
                if tool_name == 'nmap':
                    ret = nmap_scan.Nmap.nmap_import(scheduled_scan_obj)
                elif tool_name == 'nuclei':
                    ret = nuclei_scan.Nuclei.nuclei_import(scheduled_scan_obj)

                # Handle import results
                if not ret:
                    logging.getLogger(__name__).error("Module Import Failed")
                    ret_val = False

                # Restore original tool reference
                scheduled_scan_obj.current_tool = module_tool

        # Restore original scan data
        scheduled_scan_obj.scan_data = scope_obj
        return ret_val
