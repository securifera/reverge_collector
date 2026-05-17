"""Test ReconManager.get_network_interfaces using mocked netifaces."""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def manager():
    from reverge_collector.recon_manager import ReconManager

    with patch.object(ReconManager, '__init__', return_value=None):
        m = ReconManager('t', 'u')
    return m


def test_get_network_interfaces_skips_loopback(manager):
    fake_netifaces = MagicMock()
    fake_netifaces.interfaces.return_value = ['lo', 'eth0']
    fake_netifaces.AF_INET = 2
    fake_netifaces.AF_LINK = 17

    def fake_ifaddresses(iface):
        if iface == 'lo':
            return {2: [{'addr': '127.0.0.1', 'netmask': '255.0.0.0'}]}
        else:
            return {
                2: [{'addr': '10.0.0.1', 'netmask': '255.255.255.0'}],
                17: [{'addr': '00:11:22:33:44:55'}],
            }

    fake_netifaces.ifaddresses.side_effect = fake_ifaddresses

    with patch('reverge_collector.recon_manager.netifaces', fake_netifaces):
        out = manager.get_network_interfaces()
    assert 'lo' not in out
    assert 'eth0' in out
    assert out['eth0']['ipv4_addr'] == '10.0.0.1'
    assert out['eth0']['mac_address'] == '00:11:22:33:44:55'


def test_get_network_interfaces_skips_iface_without_ipv4(manager):
    fake_netifaces = MagicMock()
    fake_netifaces.interfaces.return_value = ['ipv6_only', 'eth0']
    fake_netifaces.AF_INET = 2
    fake_netifaces.AF_LINK = 17

    def fake_ifaddresses(iface):
        if iface == 'ipv6_only':
            return {17: [{'addr': '00:00:00:00:00:01'}]}  # no AF_INET
        else:
            return {
                2: [{'addr': '10.0.0.1', 'netmask': '255.255.255.0'}],
                17: [{'addr': '00:11:22:33:44:55'}],
            }

    fake_netifaces.ifaddresses.side_effect = fake_ifaddresses
    with patch('reverge_collector.recon_manager.netifaces', fake_netifaces):
        out = manager.get_network_interfaces()
    assert 'ipv6_only' not in out
    assert 'eth0' in out


def test_get_network_interfaces_handles_iface_without_mac(manager):
    fake_netifaces = MagicMock()
    fake_netifaces.interfaces.return_value = ['eth0']
    fake_netifaces.AF_INET = 2
    fake_netifaces.AF_LINK = 17
    fake_netifaces.ifaddresses.return_value = {
        2: [{'addr': '10.0.0.1', 'netmask': '255.255.255.0'}],
        # No AF_LINK
    }
    with patch('reverge_collector.recon_manager.netifaces', fake_netifaces):
        out = manager.get_network_interfaces()
    assert out['eth0']['mac_address'] == ''


def test_toggle_poller_flips_enabled():
    """toggle_poller is on ScheduledScanThread, not ReconManager."""
    from reverge_collector.recon_manager import ScheduledScanThread

    with patch.object(ScheduledScanThread, '__init__', return_value=None):
        t = ScheduledScanThread(MagicMock())
    t._enabled = True
    t.toggle_poller()
    assert t._enabled is False
    t.toggle_poller()
    assert t._enabled is True


def test_catch_failure_records_exception():
    from reverge_collector.recon_manager import ScheduledScanThread

    with patch.object(ScheduledScanThread, '__init__', return_value=None):
        t = ScheduledScanThread(MagicMock())
    task = MagicMock()
    exc = RuntimeError('boom')
    t.catch_failure(task, exc)
    assert t.failed_task_exception == (task, exc)
