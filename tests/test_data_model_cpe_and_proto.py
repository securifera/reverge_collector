"""Tests for the Cpe, ApplicationProtocol, OperatingSystem record classes
and small ScanData branches that aren't covered by the basic ScanData tests."""

from __future__ import annotations

import base64

import pytest

from reverge_collector import data_model
from reverge_collector.data_model import (
    ApplicationProtocol,
    Cpe,
    OperatingSystem,
    RecordTag,
    ScanData,
    WebComponent,
)
from reverge_collector.scan_utils import get_port_byte_array


def _scope(obj_list, port_list_str='443'):
    return {
        'b64_port_bitmap': base64.b64encode(get_port_byte_array(port_list_str)).decode(),
        'obj_list': obj_list,
    }


# ===========================================================================
# Cpe property + serialization
# ===========================================================================


class TestCpe:
    def test_assembles_cpe_string_with_defaults(self):
        c = Cpe()
        c.product = 'nginx'
        assert c.cpe == 'cpe:2.3:a:*:nginx:*:*:*:*:*:*:*:*'

    def test_assembles_cpe_with_vendor_and_version(self):
        c = Cpe()
        c.vendor = 'nginx'
        c.product = 'nginx'
        c.version = '1.21.0'
        assert c.cpe == 'cpe:2.3:a:nginx:nginx:1.21.0:*:*:*:*:*:*:*'

    def test_returns_none_when_product_missing(self):
        c = Cpe()
        assert c.cpe is None

    def test_cpe_setter_parses_full_string(self):
        c = Cpe()
        c.cpe = 'cpe:2.3:a:apache:httpd:2.4.52:*:*:*:*:*:*:*'
        assert c.part == 'a'
        assert c.vendor == 'apache'
        assert c.product == 'httpd'
        assert c.version == '2.4.52'

    def test_cpe_setter_ignores_invalid_strings(self):
        c = Cpe()
        c.product = 'before'
        c.cpe = 'not-a-cpe'
        # Existing product preserved
        assert c.product == 'before'

    def test_cpe_setter_handles_truncated_string(self):
        c = Cpe()
        c.product = 'before'
        c.cpe = 'cpe:2.3:a'  # too few fields
        # Falls through without raising; product unchanged
        assert c.product == 'before'

    def test_cpe_setter_treats_star_vendor_as_empty(self):
        c = Cpe()
        c.cpe = 'cpe:2.3:a:*:thing:1.0:*:*:*:*:*:*:*'
        assert c.vendor == ''
        assert c.product == 'thing'

    def test_cpe_setter_treats_star_version_as_none(self):
        c = Cpe()
        c.cpe = 'cpe:2.3:a:vendor:thing:*:*:*:*:*:*:*:*'
        assert c.version is None

    def test_name_alias_reads_product(self):
        c = Cpe()
        c.product = 'nginx'
        assert c.name == 'nginx'

    def test_name_alias_writes_product(self):
        c = Cpe()
        c.name = 'jquery'
        assert c.product == 'jquery'

    def test_web_component_alias_is_cpe(self):
        # The legacy WebComponent alias should still resolve to Cpe
        assert WebComponent is Cpe

    def test_data_to_jsonable_includes_name_for_backcompat(self):
        c = Cpe()
        c.vendor = 'apache'
        c.product = 'httpd'
        c.version = '2.4'
        d = c._data_to_jsonable()
        assert d == {
            'vendor': 'apache',
            'product': 'httpd',
            'part': 'a',
            'name': 'httpd',
            'version': '2.4',
        }

    def test_from_jsonsable_accepts_legacy_name(self):
        c = Cpe()
        c.from_jsonsable({'name': 'tomcat', 'vendor': 'apache'})
        assert c.product == 'tomcat'
        assert c.vendor == 'apache'

    def test_from_jsonsable_raises_when_no_product(self):
        c = Cpe()
        with pytest.raises(Exception, match='Invalid CPE'):
            c.from_jsonsable({'vendor': 'apache'})


# ===========================================================================
# ApplicationProtocol
# ===========================================================================


class TestApplicationProtocol:
    def test_data_to_jsonable_without_description(self):
        p = ApplicationProtocol()
        p.name = 'http'
        assert p._data_to_jsonable() == {'name': 'http'}

    def test_data_to_jsonable_with_description(self):
        p = ApplicationProtocol()
        p.name = 'ssh'
        p.description = 'Secure Shell'
        assert p._data_to_jsonable() == {'name': 'ssh', 'description': 'Secure Shell'}

    def test_from_jsonsable_loads_name_and_description(self):
        p = ApplicationProtocol()
        p.from_jsonsable({'name': 'https', 'description': 'TLS HTTP'})
        assert p.name == 'https'
        assert p.description == 'TLS HTTP'

    def test_from_jsonsable_raises_when_name_missing(self):
        p = ApplicationProtocol()
        with pytest.raises(Exception, match='Invalid ApplicationProtocol'):
            p.from_jsonsable({'description': 'no name'})


# ===========================================================================
# OperatingSystem.from_jsonsable
# ===========================================================================


class TestOperatingSystem:
    def test_from_jsonsable_loads_name_and_version(self):
        o = OperatingSystem()
        o.from_jsonsable({'name': 'Linux', 'version': '5.10'})
        assert o.name == 'Linux'
        assert o.version == '5.10'

    def test_data_to_jsonable_with_version(self):
        o = OperatingSystem()
        o.name = 'Windows'
        o.version = '10'
        d = o._data_to_jsonable()
        assert d['name'] == 'Windows'
        assert d['version'] == '10'

    def test_data_to_jsonable_without_version(self):
        o = OperatingSystem()
        o.name = 'BSD'
        d = o._data_to_jsonable()
        assert d['name'] == 'BSD'


# ===========================================================================
# ScanData fallback branches
# ===========================================================================


def test_get_url_metadata_map_subnet_fallback_with_no_ports():
    """Subnet present but no port_list at all → fallback path returns empty."""
    obj_list = [
        {
            'type': 'subnet', 'id': 's1',
            'data': {'subnet': '10.0.0.0', 'mask': 30},
            'tags': [RecordTag.SCOPE.value],
        },
    ]
    sd = ScanData({'obj_list': obj_list})  # no b64_port_bitmap
    out = sd.get_url_metadata_map()
    assert out == {}


def test_get_url_metadata_map_subnet_with_invalid_cidr_skipped():
    """A subnet with an unparseable subnet/mask combination is skipped."""
    obj_list = [
        {
            'type': 'subnet', 'id': 's1',
            # mask='-1' will fail ipaddress.ip_network()
            'data': {'subnet': '10.0.0.0', 'mask': -1},
            'tags': [RecordTag.SCOPE.value],
        },
    ]
    sd = ScanData(_scope(obj_list, port_list_str='80'))
    out = sd.get_url_metadata_map()
    # No URLs because the subnet was skipped
    assert out == {}
