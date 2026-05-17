"""Tests for Netexec._generate_netexec_modules (protocol + module enum)."""

from __future__ import annotations

from unittest.mock import patch


_NETEXEC_H_OUTPUT = """
usage: netexec [-h] {ldap,smb,winrm,...}

Available Protocols:
    smb              SMB enumeration
    ldap             LDAP queries
    winrm            WinRM operations
"""


_NETEXEC_SMB_L_OUTPUT = """
[*] enum_av             Enumerate AV products
[*] enum_dns            Enumerate DNS records
"""


_NETEXEC_LDAP_L_OUTPUT = """
[*] adcs                Find ADCS endpoints
"""


def _stub(stdout='', stderr='', exit_code=0):
    return {'stdout': stdout, 'stderr': stderr, 'exit_code': exit_code}


def test_returns_empty_when_help_fails():
    from reverge_collector.netexec_scan import Netexec

    with patch('reverge_collector.netexec_scan.process_wrapper',
               return_value=_stub(exit_code=2)):
        assert Netexec._generate_netexec_modules() == []


def test_returns_empty_when_no_protocols_section():
    from reverge_collector.netexec_scan import Netexec

    with patch('reverge_collector.netexec_scan.process_wrapper',
               return_value=_stub(stdout='no protocols here')):
        assert Netexec._generate_netexec_modules() == []


def test_parses_protocols_and_modules():
    from reverge_collector.netexec_scan import Netexec

    def _side(cmd_args, **kwargs):
        # First call: -h to enumerate protocols
        if cmd_args[-1] == '-h':
            return _stub(stdout=_NETEXEC_H_OUTPUT)
        # Per-protocol: <netexec> <proto> -L
        if cmd_args[-2] == 'smb':
            return _stub(stdout=_NETEXEC_SMB_L_OUTPUT)
        if cmd_args[-2] == 'ldap':
            return _stub(stdout=_NETEXEC_LDAP_L_OUTPUT)
        if cmd_args[-2] == 'winrm':
            return _stub(stdout='')
        return _stub()

    with patch('reverge_collector.netexec_scan.process_wrapper', side_effect=_side):
        modules = Netexec._generate_netexec_modules()

    names = [m.name for m in modules]
    assert 'smb_enum_av' in names
    assert 'smb_enum_dns' in names
    assert 'ldap_adcs' in names
    # Args carry "<proto> -M <name>"
    av = next(m for m in modules if m.name == 'smb_enum_av')
    assert av.args == 'smb -M enum_av'
    assert av.description == 'Enumerate AV products'


def test_protocol_module_listing_failure_is_skipped():
    from reverge_collector.netexec_scan import Netexec

    def _side(cmd_args, **kwargs):
        if cmd_args[-1] == '-h':
            return _stub(stdout=_NETEXEC_H_OUTPUT)
        if cmd_args[-2] == 'smb':
            return _stub(exit_code=99)  # fails — skip this protocol
        if cmd_args[-2] == 'ldap':
            return _stub(stdout=_NETEXEC_LDAP_L_OUTPUT)
        return _stub()

    with patch('reverge_collector.netexec_scan.process_wrapper', side_effect=_side):
        modules = Netexec._generate_netexec_modules()
    names = [m.name for m in modules]
    # smb was skipped, ldap was kept
    assert all('smb_' not in n for n in names)
    assert 'ldap_adcs' in names


def test_protocol_module_listing_exception_is_caught():
    from reverge_collector.netexec_scan import Netexec

    call_count = [0]

    def _side(cmd_args, **kwargs):
        call_count[0] += 1
        if cmd_args[-1] == '-h':
            return _stub(stdout=_NETEXEC_H_OUTPUT)
        if cmd_args[-2] == 'smb':
            raise RuntimeError('subprocess died')
        if cmd_args[-2] == 'ldap':
            return _stub(stdout=_NETEXEC_LDAP_L_OUTPUT)
        return _stub()

    with patch('reverge_collector.netexec_scan.process_wrapper', side_effect=_side):
        modules = Netexec._generate_netexec_modules()
    # Crashed on smb but recovered for ldap
    names = [m.name for m in modules]
    assert 'ldap_adcs' in names


def test_file_not_found_returns_empty():
    from reverge_collector.netexec_scan import Netexec

    with patch('reverge_collector.netexec_scan.process_wrapper',
               side_effect=FileNotFoundError('no netexec')):
        assert Netexec._generate_netexec_modules() == []
