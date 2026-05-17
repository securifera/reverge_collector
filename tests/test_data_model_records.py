"""Tests for the Record subclasses in reverge_collector.data_model:
Subnet, Host, Port, Domain, Cpe, ApplicationProtocol, OperatingSystem,
Vuln, ListItem, Screenshot, CollectionModule, Tool.

These are pure-logic data carriers — __init__, _data_to_jsonable,
to_jsonable, from_jsonsable patterns. No scanner binaries required.
"""

import pytest
from reverge_collector import data_model

# ---------------------------------------------------------------------------
# Record base — to_jsonable wraps any subclass result with id/type/parent
# ---------------------------------------------------------------------------


def test_record_init_auto_generates_id():
    """Record() with no id → auto-generates a hex UUID."""
    r = data_model.Record()
    assert isinstance(r.id, str)
    assert len(r.id) >= 16  # uuid hex is 32 chars


def test_record_init_uses_provided_id():
    r = data_model.Record(id='custom-id')
    assert r.id == 'custom-id'


def test_record_to_jsonable_wraps_no_parent_no_data():
    r = data_model.Record(id='r1')
    out = r.to_jsonable()
    assert out['id'] == 'r1'
    assert out['type'] == 'record'
    assert out['parent'] is None
    assert out['data'] is None


def test_record_to_jsonable_includes_parent_type_and_id():
    parent = data_model.Host(id='h1')
    r = data_model.Record(id='r1', parent=parent)
    out = r.to_jsonable()
    assert out['parent'] == {'type': 'host', 'id': 'h1'}


# ---------------------------------------------------------------------------
# Subnet
# ---------------------------------------------------------------------------


def test_subnet_init_defaults_none():
    s = data_model.Subnet()
    assert s.subnet is None
    assert s.mask is None


def test_subnet_from_jsonsable_sets_fields():
    s = data_model.Subnet()
    s.from_jsonsable({'subnet': '10.0.0.0', 'mask': '24'})
    assert s.subnet == '10.0.0.0'
    assert s.mask == '24'


def test_subnet_from_jsonsable_raises_on_missing_fields():
    s = data_model.Subnet()
    with pytest.raises(Exception, match='Invalid subnet object'):
        s.from_jsonsable({})


# ---------------------------------------------------------------------------
# Host
# ---------------------------------------------------------------------------


def test_host_data_to_jsonable_ipv4():
    h = data_model.Host(id='h1')
    h.ipv4_addr = '1.2.3.4'
    assert h._data_to_jsonable() == {'ipv4_addr': '1.2.3.4'}


def test_host_data_to_jsonable_includes_credential():
    h = data_model.Host()
    h.ipv4_addr = '10.0.0.1'
    h.credential = {'credential_id': 'cred-xyz'}
    out = h._data_to_jsonable()
    assert out['credential'] == {'credential_id': 'cred-xyz'}


def test_host_data_to_jsonable_empty_when_no_ip():
    """No ipv4/ipv6/credential → empty dict."""
    h = data_model.Host()
    assert h._data_to_jsonable() == {}


def test_host_from_jsonsable_parses_ipv4():
    h = data_model.Host()
    h.from_jsonsable({'ipv4_addr': '192.168.1.1'})
    assert h.ipv4_addr == '192.168.1.1'


def test_host_from_jsonsable_with_credential_id():
    h = data_model.Host()
    h.from_jsonsable({'ipv4_addr': '1.1.1.1', 'credential_id': 42})
    assert h.credential == {'credential_id': '42'}


def test_host_from_jsonsable_raises_on_bad_ip():
    h = data_model.Host()
    with pytest.raises(Exception, match='Invalid host object'):
        h.from_jsonsable({'ipv4_addr': 'not-an-ip'})


def test_host_to_jsonable_type_is_lowercased_class():
    h = data_model.Host(id='hh')
    h.ipv4_addr = '8.8.8.8'
    out = h.to_jsonable()
    assert out['type'] == 'host'
    assert out['data']['ipv4_addr'] == '8.8.8.8'


# ---------------------------------------------------------------------------
# Port
# ---------------------------------------------------------------------------


def test_port_init_parent_is_host_with_id():
    p = data_model.Port(parent_id='hh', id='pp')
    assert p.id == 'pp'
    assert p.parent.id == 'hh'
    assert isinstance(p.parent, data_model.Host)


def test_port_data_to_jsonable_includes_secure():
    p = data_model.Port(parent_id='h')
    p.port = '443'
    p.proto = 6
    p.secure = True
    out = p._data_to_jsonable()
    assert out == {'port': '443', 'proto': 6, 'secure': True}


def test_port_from_jsonsable_secure_int_one():
    p = data_model.Port(parent_id='h')
    p.from_jsonsable({'port': '8080', 'proto': 6, 'secure': 1})
    assert p.port == '8080'
    assert p.proto == 6
    assert p.secure is True


def test_port_from_jsonsable_secure_int_zero():
    p = data_model.Port(parent_id='h')
    p.from_jsonsable({'port': 80, 'proto': 6, 'secure': 0})
    assert p.secure is False


def test_port_from_jsonsable_with_credential_id():
    p = data_model.Port(parent_id='h')
    p.from_jsonsable({'port': 22, 'proto': 6, 'credential_id': 999})
    assert p.credential == {'credential_id': '999'}


def test_port_from_jsonsable_raises_on_missing_port():
    p = data_model.Port(parent_id='h')
    with pytest.raises(Exception, match='Invalid port object'):
        p.from_jsonsable({})


# ---------------------------------------------------------------------------
# Domain
# ---------------------------------------------------------------------------


def test_domain_data_to_jsonable_name_only():
    d = data_model.Domain(parent_id='h')
    d.name = 'example.com'
    assert d._data_to_jsonable() == {'name': 'example.com'}


def test_domain_data_to_jsonable_with_credential():
    d = data_model.Domain(parent_id='h')
    d.name = 'a.com'
    d.credential_id = 'cred-1'
    out = d._data_to_jsonable()
    assert out['credential_id'] == 'cred-1'


def test_domain_from_jsonsable_sets_name():
    d = data_model.Domain(parent_id='h')
    d.from_jsonsable({'name': 'sub.example.com'})
    assert d.name == 'sub.example.com'


def test_domain_from_jsonsable_with_credential_id_coerces_to_str():
    d = data_model.Domain(parent_id='h')
    d.from_jsonsable({'name': 'x', 'credential_id': 555})
    assert d.credential_id == '555'


def test_domain_from_jsonsable_raises_on_missing_name():
    d = data_model.Domain(parent_id='h')
    with pytest.raises(Exception, match='Invalid domain object'):
        d.from_jsonsable({})


# ---------------------------------------------------------------------------
# Cpe (back-compat WebComponent)
# ---------------------------------------------------------------------------


def test_cpe_init_defaults():
    c = data_model.Cpe(parent_id='p')
    assert c.vendor == ''
    assert c.product is None
    assert c.version is None
    assert c.part == 'a'


def test_cpe_name_alias_for_product():
    c = data_model.Cpe(parent_id='p')
    c.name = 'nginx'
    assert c.product == 'nginx'
    assert c.name == 'nginx'


def test_cpe_property_assembles_uri():
    c = data_model.Cpe(parent_id='p')
    c.vendor = 'acme'
    c.product = 'widget'
    c.version = '1.0'
    assert c.cpe == 'cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*'


def test_cpe_property_returns_none_without_product():
    c = data_model.Cpe(parent_id='p')
    assert c.cpe is None


def test_cpe_property_uses_wildcards_for_empty_fields():
    c = data_model.Cpe(parent_id='p')
    c.product = 'tool'
    # vendor='' / version=None → both '*' in CPE string
    assert c.cpe == 'cpe:2.3:a:*:tool:*:*:*:*:*:*:*:*'


def test_cpe_setter_parses_full_cpe_string():
    c = data_model.Cpe(parent_id='p')
    c.cpe = 'cpe:2.3:a:apache:httpd:2.4:*:*:*:*:*:*:*'
    assert c.vendor == 'apache'
    assert c.product == 'httpd'
    assert c.version == '2.4'
    assert c.part == 'a'


def test_cpe_setter_treats_wildcards_as_empty():
    c = data_model.Cpe(parent_id='p')
    c.cpe = 'cpe:2.3:a:*:something:*:*:*:*:*:*:*:*'
    assert c.vendor == ''
    assert c.product == 'something'
    assert c.version is None


def test_cpe_setter_ignores_non_cpe_strings():
    c = data_model.Cpe(parent_id='p')
    c.vendor = 'pre'
    c.cpe = 'not-a-cpe-string'
    # State unchanged
    assert c.vendor == 'pre'


def test_cpe_setter_ignores_empty():
    c = data_model.Cpe(parent_id='p')
    c.vendor = 'x'
    c.cpe = ''
    assert c.vendor == 'x'


def test_cpe_data_to_jsonable_emits_backcompat_name():
    """Always emit 'name' alongside 'product' for old reverge consumers."""
    c = data_model.Cpe(parent_id='p')
    c.product = 'apache'
    c.vendor = 'apache'
    c.version = '2.4'
    out = c._data_to_jsonable()
    assert out['name'] == 'apache'
    assert out['product'] == 'apache'
    assert out['version'] == '2.4'


def test_cpe_data_to_jsonable_omits_version_when_none():
    c = data_model.Cpe(parent_id='p')
    c.product = 'tool'
    out = c._data_to_jsonable()
    assert 'version' not in out


def test_cpe_from_jsonsable_accepts_legacy_name_field():
    c = data_model.Cpe(parent_id='p')
    c.from_jsonsable({'name': 'legacy', 'vendor': 'v'})
    assert c.product == 'legacy'


def test_cpe_from_jsonsable_prefers_product_over_name():
    c = data_model.Cpe(parent_id='p')
    c.from_jsonsable({'product': 'new', 'name': 'old'})
    assert c.product == 'new'


def test_cpe_from_jsonsable_raises_without_product():
    c = data_model.Cpe(parent_id='p')
    with pytest.raises(Exception, match='Invalid CPE object'):
        c.from_jsonsable({})


# ---------------------------------------------------------------------------
# ApplicationProtocol
# ---------------------------------------------------------------------------


def test_application_protocol_data_to_jsonable():
    ap = data_model.ApplicationProtocol(parent_id='p')
    ap.name = 'https'
    out = ap._data_to_jsonable()
    assert out == {'name': 'https'}


def test_application_protocol_from_jsonsable_sets_name():
    ap = data_model.ApplicationProtocol(parent_id='p')
    ap.from_jsonsable({'name': 'ssh'})
    assert ap.name == 'ssh'


def test_application_protocol_from_jsonsable_raises_on_missing_name():
    ap = data_model.ApplicationProtocol(parent_id='p')
    with pytest.raises(Exception, match='Invalid ApplicationProtocol'):
        ap.from_jsonsable({})


# ---------------------------------------------------------------------------
# OperatingSystem
# ---------------------------------------------------------------------------


def test_operating_system_data_to_jsonable_minimal():
    os_obj = data_model.OperatingSystem(parent_id='h')
    os_obj.name = 'Linux'
    out = os_obj._data_to_jsonable()
    assert out['name'] == 'Linux'


def test_operating_system_data_to_jsonable_with_version():
    os_obj = data_model.OperatingSystem(parent_id='h')
    os_obj.name = 'Ubuntu'
    os_obj.version = '22.04'
    out = os_obj._data_to_jsonable()
    assert out['name'] == 'Ubuntu'
    assert out['version'] == '22.04'


def test_operating_system_from_jsonsable_sets_fields():
    os_obj = data_model.OperatingSystem(parent_id='h')
    os_obj.from_jsonsable({'name': 'Darwin', 'version': '23.0'})
    assert os_obj.name == 'Darwin'
    assert os_obj.version == '23.0'


# ---------------------------------------------------------------------------
# Vuln
# ---------------------------------------------------------------------------


def test_vuln_data_to_jsonable_name_only():
    v = data_model.Vuln(parent_id='p')
    v.name = 'CVE-2024-1234'
    out = v._data_to_jsonable()
    assert out['name'] == 'CVE-2024-1234'


def test_vuln_from_jsonsable_sets_optional_fields():
    v = data_model.Vuln(parent_id='p')
    v.from_jsonsable(
        {'name': 'XSS', 'vuln_details': 'Reflected XSS', 'endpoint_id': 'ep-1'}
    )
    assert v.name == 'XSS'
    assert v.vuln_details == 'Reflected XSS'
    assert v.endpoint_id == 'ep-1'


def test_vuln_from_jsonsable_raises_on_missing_name():
    v = data_model.Vuln(parent_id='p')
    with pytest.raises(Exception, match='Invalid vuln object'):
        v.from_jsonsable({})


# ---------------------------------------------------------------------------
# ListItem
# ---------------------------------------------------------------------------


def test_list_item_data_to_jsonable_emits_path_and_hash():
    """ListItem._data_to_jsonable returns the {'path', 'path_hash'} pair."""
    li = data_model.ListItem()
    li.web_path = '/admin'
    li.web_path_hash = 'sha1hex'
    out = li._data_to_jsonable()
    assert out == {'path': '/admin', 'path_hash': 'sha1hex'}


def test_list_item_from_jsonsable_sets_web_path_fields():
    li = data_model.ListItem()
    li.from_jsonsable({'path': '/foo', 'path_hash': 'abc123'})
    assert li.web_path == '/foo'
    assert li.web_path_hash == 'abc123'


# ---------------------------------------------------------------------------
# Tool — top-level record type
# ---------------------------------------------------------------------------


def test_tool_init_uses_tool_id_as_record_id():
    t = data_model.Tool('nmap_001')
    assert t.id == 'nmap_001'
    assert t.parent is None
