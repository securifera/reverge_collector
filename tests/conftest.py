import pytest
from unittest.mock import patch

from waluigi.data_model import WaluigiTool
from waluigi.recon_manager import ReconManager


@pytest.fixture(autouse=True)
def change_test_dir(monkeypatch):
    monkeypatch.chdir("/tmp")


@pytest.fixture
def mock_update_collector_and_session_key():
    with patch.object(ReconManager, 'update_collector',
                      return_value={'tool_name_id_map': {'masscan': '323482209708942791672081599309763638881',
                                                         'subfinder': '323482209708942791672081599309763638882',
                                                         'httpx': '323482209708942791672081599309763638883',
                                                         'nmap': '323482209708942791672081599309763638884',
                                                         'nuclei': '323482209708942791672081599309763638885',
                                                         'pyshot': '323482209708942791672081599309763638886',
                                                         'shodan': '323482209708942791672081599309763638887',
                                                         'webcap': '323482209708942791672081599309763638888',
                                                         'feroxbuster': '323482209708942791672081599309763638889',
                                                         'gau': '323482209708942791672081599309763638890',
                                                         'python': '323482209708942791672081599309763638891',
                                                         'iis_short_scan': '323482209708942791672081599309763638892',
                                                         'ipthc': '323482209708942791672081599309763638893',
                                                         'crapsecrets': '323482209708942791672081599309763638894',
                                                         'netexec': '323482209708942791672081599309763638895',
                                                         'metasploit': '323482209708942791672081599309763638896'}}) as mock_update_collector, \
            patch.object(ReconManager, '_get_session_key', return_value='mock_session_key') as mock_get_session_key, \
            patch.object(ReconManager, 'update_scan_status', return_value=''):
        yield mock_update_collector, mock_get_session_key


@pytest.fixture
def recon_manager(mock_update_collector_and_session_key):
    token = "test_token"
    manager_url = "http://test_manager_url"

    def patched_to_jsonable(self):
        ret_dict = {
            'name': self.name,
            'tool_type': self.collector_type,
            'scan_order': self.scan_order,
            'args': self.args,
            'description': self.description,
            'project_url': self.project_url,
            'input_records': [input_type.value for input_type in self.input_records],
            'output_records': [output_type.value for output_type in self.output_records],
            'modules': []
        }
        return ret_dict

    mgr = None
    with patch.object(WaluigiTool, 'to_jsonable', patched_to_jsonable):
        mgr = ReconManager(token, manager_url)

    return mgr


def get_tool_id(recon_manager, tool_name):
    """Get the tool ID for the configured tool name."""
    tool_id_instance = None
    tool_map = recon_manager.get_tool_map()
    for tool_id, tool in tool_map.items():
        if tool.name == tool_name:
            tool_id_instance = tool_id
            break

    if tool_id_instance is None:
        raise AssertionError(f"{tool_name} tool not found in tool map")

    return tool_id_instance
