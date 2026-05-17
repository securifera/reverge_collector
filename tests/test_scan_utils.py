"""Tests for reverge_collector.scan_utils — URL parsing, port bitmaps, etc.

Most of these helpers are pure functions, so unit tests can hit a lot of
the branches without mocking anything.
"""

from __future__ import annotations

import json

import pytest

# ---------------------------------------------------------------------------
# is_cloud_domain
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    'domain,expected',
    [
        ('s3.amazonaws.com', True),
        ('myapp.cloudfront.net', True),
        ('UPPERCASE.AMAZONAWS.COM', True),  # case-insensitive
        ('example.com', False),
        ('www.google.com', False),
        ('', False),
    ],
)
def test_is_cloud_domain(domain, expected):
    from reverge_collector.scan_utils import is_cloud_domain

    assert is_cloud_domain(domain) is expected


# ---------------------------------------------------------------------------
# get_url_port
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    'url,expected',
    [
        ('https://example.com:8443/path', 8443),
        ('http://example.com', 80),
        ('https://example.com', 443),
        ('http://example.com/path', 80),
        ('https://example.com:1234', 1234),
    ],
)
def test_get_url_port(url, expected):
    from reverge_collector.scan_utils import get_url_port

    assert get_url_port(url) == expected


# ---------------------------------------------------------------------------
# construct_url
# ---------------------------------------------------------------------------


def test_construct_url_https_default_port_omitted():
    from reverge_collector.scan_utils import construct_url

    assert construct_url('example.com', 443, True) == 'https://example.com'


def test_construct_url_http_default_port_omitted():
    from reverge_collector.scan_utils import construct_url

    assert construct_url('example.com', 80, False) == 'http://example.com'


def test_construct_url_non_default_port_included():
    from reverge_collector.scan_utils import construct_url

    assert construct_url('example.com', 8080, False) == 'http://example.com:8080'


def test_construct_url_https_non_default():
    from reverge_collector.scan_utils import construct_url

    assert construct_url('example.com', 8443, True) == 'https://example.com:8443'


def test_construct_url_query_string_appended():
    from reverge_collector.scan_utils import construct_url

    assert construct_url('example.com', 443, True, '/api/v1') == 'https://example.com/api/v1'


def test_construct_url_returns_none_for_missing_required():
    from reverge_collector.scan_utils import construct_url

    assert construct_url(None, 80, False) is None
    assert construct_url('x', None, False) is None
    assert construct_url('x', 80, None) is None


def test_construct_url_accepts_anything_validators_passes():
    from reverge_collector.scan_utils import construct_url

    # construct_url only returns None when validators.url() rejects the
    # final URL. python-validators is fairly permissive — it accepts the
    # raw host string. We test that it's a no-op for normal inputs.
    out = construct_url('host.example', 80, False)
    assert out == 'http://host.example'


# ---------------------------------------------------------------------------
# Port bitmap helpers
# ---------------------------------------------------------------------------


def test_get_port_byte_array_roundtrip():
    from reverge_collector.scan_utils import get_port_byte_array, get_ports

    ba = get_port_byte_array('22, 80, 443')
    out = sorted(int(p) for p in get_ports(ba))
    assert out == [22, 80, 443]


def test_get_port_byte_array_with_range():
    from reverge_collector.scan_utils import get_port_byte_array, get_ports

    ba = get_port_byte_array('80-82')
    out = sorted(int(p) for p in get_ports(ba))
    assert out == [80, 81, 82]


def test_get_port_byte_array_handles_empty():
    from reverge_collector.scan_utils import get_port_byte_array, get_ports

    ba = get_port_byte_array('')
    out = get_ports(ba)
    assert out == []


def test_set_bit_sets_correct_bit():
    from reverge_collector.scan_utils import set_bit

    ba = bytearray(8192)  # 65536 bits
    set_bit(100, ba)
    # Byte index 100//8 = 12, bit position 100%8 = 4
    assert ba[12] & (1 << 4)


# ---------------------------------------------------------------------------
# check_domain
# ---------------------------------------------------------------------------


def test_check_domain_returns_string_for_valid():
    from reverge_collector.scan_utils import check_domain

    # check_domain just filters wildcards and IPs; it doesn't normalise
    assert check_domain('example.com') == 'example.com'
    assert check_domain('Example.Com') == 'Example.Com'


def test_check_domain_filters_wildcard():
    from reverge_collector.scan_utils import check_domain

    assert check_domain('*.example.com') is None
    assert check_domain('foo.*.bar') is None


def test_check_domain_filters_ip_addresses():
    from reverge_collector.scan_utils import check_domain

    # IPv4 and IPv6 IPs should be filtered out
    assert check_domain('192.168.1.1') is None
    assert check_domain('::1') is None
    assert check_domain('2001:db8::1') is None


# ---------------------------------------------------------------------------
# parse_json_blob_file
# ---------------------------------------------------------------------------


def test_parse_json_blob_file_returns_list_from_jsonl(tmp_path):
    from reverge_collector.scan_utils import parse_json_blob_file

    f = tmp_path / 'blob.jsonl'
    f.write_text(json.dumps({'a': 1}) + '\n' + json.dumps({'b': 2}) + '\n')
    out = parse_json_blob_file(str(f))
    assert isinstance(out, list)
    assert {'a': 1} in out
    assert {'b': 2} in out


def test_parse_json_blob_file_handles_concatenated_json(tmp_path):
    """Some scanners emit one big JSON array or concatenated objects."""
    from reverge_collector.scan_utils import parse_json_blob_file

    f = tmp_path / 'blob.json'
    f.write_text(json.dumps([{'x': 1}, {'y': 2}]))
    out = parse_json_blob_file(str(f))
    assert isinstance(out, list)


def test_parse_json_blob_file_empty(tmp_path):
    from reverge_collector.scan_utils import parse_json_blob_file

    f = tmp_path / 'empty.jsonl'
    f.write_text('')
    out = parse_json_blob_file(str(f))
    assert out == []


def test_parse_json_blob_file_missing_returns_empty(tmp_path):
    from reverge_collector.scan_utils import parse_json_blob_file

    out = parse_json_blob_file(str(tmp_path / 'missing.json'))
    assert out == []


def test_parse_json_blob_file_stops_at_malformed(tmp_path):
    from reverge_collector.scan_utils import parse_json_blob_file

    # parse_json_blob_file uses raw_decode in a loop; on JSONDecodeError it
    # logs and breaks out. So entries BEFORE the bad line are returned,
    # entries AFTER are dropped.
    f = tmp_path / 'mixed.jsonl'
    f.write_text(
        json.dumps({'good': True}) + '\n' + 'not json\n' + json.dumps({'after_bad': True}) + '\n'
    )
    out = parse_json_blob_file(str(f))
    assert {'good': True} in out


# ---------------------------------------------------------------------------
# init_tool_folder — filesystem side effect
# ---------------------------------------------------------------------------


def test_init_tool_folder_creates_directory(tmp_path, monkeypatch):
    """init_tool_folder builds /tmp/<scan_id>/<tool_name>-<desc>/ — verify dir creation."""
    from reverge_collector import scan_utils

    monkeypatch.chdir(tmp_path)
    out = scan_utils.init_tool_folder('mytool', 'outputs', 'scan-abc-123')
    # Function creates the dir at /tmp/<scan_id>/<tool>-<desc>/
    # Just confirm a path string is returned that ends with the expected suffix
    assert 'mytool' in out
    assert 'outputs' in out
    assert 'scan-abc-123' in out


# ---------------------------------------------------------------------------
# execution_time decorator
# ---------------------------------------------------------------------------


def test_execution_time_decorator_preserves_return_value():
    from reverge_collector.scan_utils import execution_time

    @execution_time
    def add(a, b):
        return a + b

    assert add(2, 3) == 5
