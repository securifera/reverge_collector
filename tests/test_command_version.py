"""Tiny tests for command.py and version.py — pure dataclass + constant."""

from reverge_collector import version
from reverge_collector.command import Command


def test_version_string_present():
    assert isinstance(version.__version__, str)
    assert version.__version__  # non-empty


def test_command_defaults():
    c = Command(args=['nmap', '-sT'], output_path='/tmp/o.json')
    assert c.args == ['nmap', '-sT']
    assert c.output_path == '/tmp/o.json'
    assert c.sudo is True
    assert c.env is None


def test_command_full_init():
    c = Command(
        args=['x'],
        output_path='/o',
        sudo=False,
        env={'PATH': '/usr/bin'},
    )
    assert c.sudo is False
    assert c.env == {'PATH': '/usr/bin'}


def test_command_equality_by_value():
    a = Command(args=['n'], output_path='/o')
    b = Command(args=['n'], output_path='/o')
    assert a == b
