import pytest
from unittest.mock import patch

from waluigi.recon_manager import ReconManager


@pytest.fixture(autouse=True)
def change_test_dir(monkeypatch):
    monkeypatch.chdir("/tmp")


@pytest.fixture
def mock_update_collector_and_session_key():
    with patch.object(ReconManager, 'update_collector', return_value={'tool_name_id_map': {'masscan': '323482209708942791672081599309763638881'}}) as mock_update_collector, \
            patch.object(ReconManager, '_get_session_key', return_value='mock_session_key') as mock_get_session_key, \
            patch.object(ReconManager, 'update_scan_status', return_value=''):
        yield mock_update_collector, mock_get_session_key


@pytest.fixture
def recon_manager(mock_update_collector_and_session_key):
    token = "test_token"
    manager_url = "http://test_manager_url"
    return ReconManager(token, manager_url)
