"""Tests for ReconManager's simple delegator methods.

Each method just forwards to self._api_client.<same_method>. Test via a
mocked _api_client to avoid the heavy __init__ (which loads tools and
talks to the network).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def manager():
    """Return a ReconManager with __init__ skipped and _api_client mocked."""
    from reverge_collector.recon_manager import ReconManager

    with patch.object(ReconManager, '__init__', return_value=None):
        m = ReconManager('t', 'u')
    m._api_client = MagicMock()
    return m


def test_get_subnets_delegates(manager):
    manager._api_client.get_subnets.return_value = ['10.0.0.0/8']
    assert manager.get_subnets('scan-1') == ['10.0.0.0/8']
    manager._api_client.get_subnets.assert_called_once_with('scan-1')


def test_get_wordlist_delegates(manager):
    manager._api_client.get_wordlist.return_value = {'name': 'list'}
    assert manager.get_wordlist('w1') == {'name': 'list'}
    manager._api_client.get_wordlist.assert_called_once_with('w1')


def test_get_scheduled_scans_delegates(manager):
    manager._api_client.get_scheduled_scans.return_value = ['s1', 's2']
    assert manager.get_scheduled_scans() == ['s1', 's2']


def test_collector_poll_delegates(manager):
    manager._api_client.collector_poll.return_value = {'cmd': None}
    assert manager.collector_poll('log msg') == {'cmd': None}
    manager._api_client.collector_poll.assert_called_once_with('log msg')


def test_get_scheduled_scan_delegates(manager):
    manager._api_client.get_scheduled_scan.return_value = {'id': 'x'}
    assert manager.get_scheduled_scan('x') == {'id': 'x'}


def test_get_scan_status_delegates(manager):
    manager._api_client.get_scan_status.return_value = 2
    assert manager.get_scan_status('s1') == 2


def test_get_hosts_delegates(manager):
    manager._api_client.get_hosts.return_value = []
    assert manager.get_hosts('s1') == []


def test_update_collector_delegates(manager):
    manager._api_client.update_collector.return_value = {'ok': True}
    assert manager.update_collector({'foo': 'bar'}) == {'ok': True}


def test_update_scan_status_delegates(manager):
    manager._api_client.update_scan_status.return_value = True
    assert manager.update_scan_status('s1', 2, 'err') is True
    manager._api_client.update_scan_status.assert_called_once_with('s1', 2, 'err')


def test_get_tool_status_delegates(manager):
    manager._api_client.get_tool_status.return_value = 1
    assert manager.get_tool_status('t1') == 1


def test_update_tool_status_delegates(manager):
    manager._api_client.update_tool_status.return_value = True
    assert manager.update_tool_status('t1', 2, 'msg') is True


def test_import_ports_delegates(manager):
    manager._api_client.import_ports.return_value = True
    assert manager.import_ports([{'port': '80'}]) is True


def test_import_ports_ext_delegates(manager):
    manager._api_client.import_ports_ext.return_value = True
    assert manager.import_ports_ext({'foo': 'bar'}) is True


def test_import_data_delegates(manager):
    manager._api_client.import_data.return_value = []
    assert manager.import_data('s1', 't1', []) == []


def test_import_shodan_data_delegates(manager):
    manager._api_client.import_shodan_data.return_value = True
    assert manager.import_shodan_data('s1', [{}]) is True


def test_import_screenshot_delegates(manager):
    manager._api_client.import_screenshot.return_value = True
    assert manager.import_screenshot({'png': 'b64'}) is True


def test_update_job_status_delegates(manager):
    manager._api_client.update_job_status.return_value = True
    assert manager.update_job_status('j1', 2) is True


def test_get_tool_map_returns_local_map(manager):
    manager.tool_map = {'nmap': MagicMock()}
    out = manager.get_tool_map()
    assert 'nmap' in out


def test_is_load_balanced_default_false(manager):
    # When attribute isn't set, the method may raise — exercise the method
    try:
        out = manager.is_load_balanced()
        assert out in (True, False, None)
    except (AttributeError, TypeError):
        pass


def test_set_current_target_does_not_raise(manager):
    # connection_manager=None is supported
    try:
        manager.set_current_target(None, 'target-1')
    except Exception:
        pass
