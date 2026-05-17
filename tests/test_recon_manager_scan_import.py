"""Tests for ReconManager.scan_func / import_func and other small public methods."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def manager():
    from reverge_collector.recon_manager import ReconManager

    with patch.object(ReconManager, '__init__', return_value=None):
        m = ReconManager('t', 'u')
    m.tool_map = {}
    m._api_client = MagicMock()
    return m


def _fake_scan_input(tool_id='nmap-id'):
    return SimpleNamespace(current_tool=SimpleNamespace(id=tool_id))


class TestScanFunc:
    def test_scan_func_delegates_to_tool_in_map(self, manager):
        tool = MagicMock()
        tool.scan_func.return_value = True
        manager.tool_map = {'nmap-id': tool}

        scan = _fake_scan_input('nmap-id')
        assert manager.scan_func(scan) is True
        tool.scan_func.assert_called_once_with(scan)

    def test_scan_func_returns_false_for_unknown_tool(self, manager):
        scan = _fake_scan_input('missing-id')
        assert manager.scan_func(scan) is False


class TestImportFunc:
    def test_import_func_delegates_to_tool_in_map(self, manager):
        tool = MagicMock()
        tool.import_func.return_value = True
        manager.tool_map = {'nmap-id': tool}

        scan = _fake_scan_input('nmap-id')
        assert manager.import_func(scan) is True
        tool.import_func.assert_called_once_with(scan)

    def test_import_func_returns_false_for_unknown_tool(self, manager):
        scan = _fake_scan_input('missing-id')
        assert manager.import_func(scan) is False


class TestGetToolMap:
    def test_get_tool_map_returns_internal_map(self, manager):
        manager.tool_map = {'nmap': 'instance'}
        assert manager.get_tool_map() == {'nmap': 'instance'}


class TestIsLoadBalanced:
    def test_is_load_balanced_default_when_no_network_ifaces(self, manager):
        # Need network_ifaces attribute
        manager.network_ifaces = {}
        out = manager.is_load_balanced()
        assert isinstance(out, bool)


class TestSetCurrentTarget:
    def test_set_current_target_no_op_with_no_connection_manager(self, manager):
        # connection_manager=None should be safely handled
        manager.set_current_target(None, 'target-1')
