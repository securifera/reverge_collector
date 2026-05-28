"""Each ToolSpec subclass must declare every record type its parser creates.

When a ToolSpec's ``output_records`` is missing a record type that the parser
actually instantiates, the server-side import pipeline may filter those records
out — silent data loss. This test AST-scans every ToolSpec module for
``data_model.<Class>(...)`` calls and asserts that the corresponding
``ServerRecordType`` enum value is present in ``output_records``.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest
from reverge_collector import data_model
from reverge_collector.tool_spec import ToolSpec

TOOL_MODULES = [
    'masscan',
    'naabu_scan',
    'shodan_lookup',
    'crapsecrets_scan',
    'webcap_scan',
    'sqlmap_scan',
    'netexec_scan',
    'httpx_scan',
    'gau_scan',
    'iis_short_scan',
    'python_scan',
    'nuclei_scan',
    'metasploit_scan',
    'nmap_scan',
    'pyshot_scan',
    'ip_thc_lookup',
    'feroxbuster_scan',
    'subfinder_scan',
]

# data_model class name -> ServerRecordType enum name
CLASS_TO_RECORD_TYPE = {
    'Host': 'HOST',
    'Port': 'PORT',
    'Domain': 'DOMAIN',
    'HttpEndpoint': 'HTTP_ENDPOINT',
    'HttpEndpointData': 'HTTP_ENDPOINT_DATA',
    'Vuln': 'VULNERABILITY',
    'CollectionModule': 'COLLECTION_MODULE',
    'CollectionModuleOutput': 'COLLECTION_MODULE_OUTPUT',
    'Screenshot': 'SCREENSHOT',
    'Certificate': 'CERTIFICATE',
    'ListItem': 'LIST_ITEM',
    'Cpe': 'CPE',
    'ApplicationProtocol': 'APPLICATION_PROTOCOL',
    'WebComponent': 'WEB_COMPONENT',
    'Subnet': 'SUBNET',
    # No enum entries — record types not surfaced server-side:
    #   OperatingSystem, Credential
}

PKG_ROOT = Path(data_model.__file__).parent


def _find_tool_spec_class(module):
    for name in dir(module):
        obj = getattr(module, name)
        if isinstance(obj, type) and issubclass(obj, ToolSpec) and obj is not ToolSpec:
            return obj
    raise AssertionError(f'No ToolSpec subclass found in {module.__name__}')


def _classes_instantiated_in_module(module_name: str) -> set[str]:
    src = (PKG_ROOT / f'{module_name}.py').read_text()
    tree = ast.parse(src)
    created: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == 'data_model'
            and node.func.attr in CLASS_TO_RECORD_TYPE
        ):
            created.add(node.func.attr)
    return created


@pytest.mark.parametrize('module_name', TOOL_MODULES)
def test_output_records_covers_parser_output(module_name: str):
    module = importlib.import_module(f'reverge_collector.{module_name}')
    tool_cls = _find_tool_spec_class(module)
    declared = {rt.name for rt in tool_cls.output_records}
    created_classes = _classes_instantiated_in_module(module_name)
    expected = {CLASS_TO_RECORD_TYPE[c] for c in created_classes}

    # WEB_COMPONENT is documented as a legacy alias for CPE — accept either
    # declared name as satisfying a Cpe instantiation, since some tools still
    # declare the legacy alias for backward-compat with older reverge servers.
    missing = expected - declared
    if 'CPE' in missing and 'WEB_COMPONENT' in declared:
        missing.discard('CPE')

    assert not missing, (
        f'{module_name}.{tool_cls.__name__} parser creates '
        f'{sorted(c for c in created_classes if CLASS_TO_RECORD_TYPE[c] in missing)} '
        f'but output_records does not declare {sorted(missing)}'
    )
