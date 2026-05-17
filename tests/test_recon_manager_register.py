"""Tests for ReconManager.register_with_server."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def manager():
    """Skip ReconManager.__init__ (loads tools, talks to network) and
    set up just the attributes register_with_server reads."""
    from reverge_collector.recon_manager import ReconManager

    with patch.object(ReconManager, '__init__', return_value=None):
        m = ReconManager('t', 'u')
    m.token = 'auth-token'
    m.manager_url = 'http://server'
    m.network_ifaces = {'eth0': {'ipv4_addr': '10.0.0.1'}}
    m._collector_tools = [{'name': 'nmap'}, {'name': 'naabu'}]
    # Stand-in for the tool name → instance map; we register two scanners
    m._tool_name_inst_map = {
        'nmap': MagicMock(name='nmap_instance'),
        'naabu': MagicMock(name='naabu_instance'),
    }
    return m


def test_register_with_server_creates_api_client_and_maps_tools(manager):
    """Happy path: ApiClient constructs, update_collector returns a tool
    map, tool_map is populated with hex IDs."""
    with patch('reverge_collector.recon_manager.ApiClient') as ApiCls:
        client = MagicMock()
        client.update_collector.return_value = {
            'tool_name_id_map': {
                'nmap': 0xABC,
                'naabu': 0x123,
            }
        }
        ApiCls.return_value = client
        manager.register_with_server()

    # Tool map populated with hex IDs
    assert 'abc' in manager.tool_map
    assert '123' in manager.tool_map
    # Each maps to the corresponding instance
    assert manager.tool_map['abc'] is manager._tool_name_inst_map['nmap']
    assert manager.tool_map['123'] is manager._tool_name_inst_map['naabu']

    # ApiClient was called with the right credentials
    ApiCls.assert_called_once_with('auth-token', 'http://server')

    # update_collector got the interfaces + tools
    call_args = client.update_collector.call_args.args[0]
    assert call_args['interfaces'] == manager.network_ifaces
    assert call_args['tools'] == manager._collector_tools


def test_register_with_server_raises_session_exception_when_apiclient_fails(manager):
    from reverge_collector.recon_manager import SessionException

    with patch(
        'reverge_collector.recon_manager.ApiClient',
        side_effect=Exception('connection refused'),
    ):
        with pytest.raises(SessionException, match='session'):
            manager.register_with_server()


def test_register_with_server_raises_session_exception_when_update_collector_fails(
    manager,
):
    from reverge_collector.recon_manager import SessionException

    with patch('reverge_collector.recon_manager.ApiClient') as ApiCls:
        client = MagicMock()
        client.update_collector.side_effect = Exception('500 internal')
        ApiCls.return_value = client
        with pytest.raises(SessionException, match='register collector'):
            manager.register_with_server()


def test_register_with_server_raises_when_response_lacks_tool_name_id_map(manager):
    from reverge_collector.recon_manager import SessionException

    with patch('reverge_collector.recon_manager.ApiClient') as ApiCls:
        client = MagicMock()
        client.update_collector.return_value = {'other_key': 'value'}
        ApiCls.return_value = client
        with pytest.raises(SessionException, match='Failed to register'):
            manager.register_with_server()


def test_register_with_server_raises_when_tool_map_empty(manager):
    from reverge_collector.recon_manager import SessionException

    with patch('reverge_collector.recon_manager.ApiClient') as ApiCls:
        client = MagicMock()
        client.update_collector.return_value = {'tool_name_id_map': {}}
        ApiCls.return_value = client
        with pytest.raises(SessionException, match='Failed to register'):
            manager.register_with_server()


def test_register_with_server_raises_when_response_is_none(manager):
    from reverge_collector.recon_manager import SessionException

    with patch('reverge_collector.recon_manager.ApiClient') as ApiCls:
        client = MagicMock()
        client.update_collector.return_value = None
        ApiCls.return_value = client
        with pytest.raises(SessionException, match='Failed to register'):
            manager.register_with_server()


def test_register_with_server_skips_unknown_tool_names(manager):
    """If the server returns a tool name we don't have locally, log + skip
    (don't crash). Known tools still register."""
    with patch('reverge_collector.recon_manager.ApiClient') as ApiCls:
        client = MagicMock()
        client.update_collector.return_value = {
            'tool_name_id_map': {
                'nmap': 0xABC,
                'unknown-tool': 0xDEF,
            }
        }
        ApiCls.return_value = client
        manager.register_with_server()

    # Known one registered, unknown one skipped silently
    assert 'abc' in manager.tool_map
    assert 'def' not in manager.tool_map


# ===========================================================================
# get_tool_classes — top-level helper that loads all scanner classes
# ===========================================================================


def test_get_tool_classes_loads_all_scanner_modules():
    """Sanity check: get_tool_classes returns ToolSpec subclasses."""
    from reverge_collector import data_model

    classes = data_model.get_tool_classes()
    # Should include the well-known scanners
    names = {getattr(c, 'name', None) for c in classes}
    expected_subset = {'nmap', 'naabu', 'httpx', 'masscan'}
    assert expected_subset.issubset(names)
