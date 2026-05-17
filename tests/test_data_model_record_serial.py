"""Tests for Record subclass serialization paths in data_model.
Targets the small from_jsonsable/_data_to_jsonable/remap_ids methods that
the route tests don't exercise."""

from __future__ import annotations

import pytest

from reverge_collector import data_model
from reverge_collector.data_model import (
    Certificate,
    CollectionModule,
    CollectionModuleOutput,
    Credential,
    HttpEndpointData,
    ListItem,
    Screenshot,
    Vuln,
)


# ===========================================================================
# Vuln
# ===========================================================================


class TestVuln:
    def test_data_to_jsonable_minimal(self):
        v = Vuln()
        v.name = 'CVE-2024-0001'
        out = v._data_to_jsonable()
        assert out == {'name': 'CVE-2024-0001'}

    def test_data_to_jsonable_with_details_and_endpoint(self):
        v = Vuln()
        v.name = 'CVE-2024-0002'
        v.vuln_details = 'details here'
        v.endpoint_id = 'ep-1'
        out = v._data_to_jsonable()
        assert out == {
            'name': 'CVE-2024-0002',
            'vuln_details': 'details here',
            'endpoint_id': 'ep-1',
        }

    def test_from_jsonsable_loads_all_fields(self):
        v = Vuln()
        v.from_jsonsable({
            'name': 'CVE-X',
            'vuln_details': 'd',
            'endpoint_id': 'ep-x',
        })
        assert v.name == 'CVE-X'
        assert v.vuln_details == 'd'
        assert v.endpoint_id == 'ep-x'

    def test_from_jsonsable_raises_on_missing_name(self):
        v = Vuln()
        with pytest.raises(Exception, match='Invalid vuln'):
            v.from_jsonsable({})

    def test_remap_ids_updates_endpoint_id(self):
        v = Vuln(parent_id='parent-old')
        v.endpoint_id = 'old-ep'
        v.remap_ids({'parent-old': 'parent-new', 'old-ep': 'new-ep'})
        assert v.parent.id == 'parent-new'
        assert v.endpoint_id == 'new-ep'


# ===========================================================================
# ListItem
# ===========================================================================


class TestListItem:
    def test_from_jsonsable_defaults_to_root_when_path_none(self):
        li = ListItem()
        li.from_jsonsable({'path': None, 'path_hash': None})
        assert li.web_path == '/'
        # Hash auto-generated for the root path
        assert li.web_path_hash is not None
        assert len(li.web_path_hash) > 0


# ===========================================================================
# HttpEndpointData
# ===========================================================================


class TestHttpEndpointData:
    def test_from_jsonsable_loads_all_fields(self):
        e = HttpEndpointData()
        e.from_jsonsable({
            'title': 'Title',
            'status': 200,
            'last_modified': 12345,
            'screenshot_id': 'ss-1',
            'domain_id': 'd-1',
            'fav_icon_hash': 'fh',
            'content_length': 1024,
        })
        assert e.title == 'Title'
        assert e.status == 200
        assert e.last_modified == 12345
        assert e.screenshot_id == 'ss-1'
        assert e.domain_id == 'd-1'
        assert e.fav_icon_hash == 'fh'
        assert e.content_length == 1024

    def test_from_jsonsable_falsy_fav_icon_hash_ignored(self):
        e = HttpEndpointData()
        e.from_jsonsable({'fav_icon_hash': ''})
        assert e.fav_icon_hash is None

    def test_remap_ids_remaps_domain_and_screenshot(self):
        e = HttpEndpointData(parent_id='ep-old')
        e.domain_id = 'old-d'
        e.screenshot_id = 'old-ss'
        e.remap_ids({'ep-old': 'ep-new', 'old-d': 'new-d', 'old-ss': 'new-ss'})
        assert e.parent.id == 'ep-new'
        assert e.domain_id == 'new-d'
        assert e.screenshot_id == 'new-ss'


# ===========================================================================
# CollectionModuleOutput
# ===========================================================================


class TestCollectionModuleOutput:
    def test_from_jsonsable_required_fields(self):
        o = CollectionModuleOutput()
        o.from_jsonsable({'output': 'text', 'port_id': 'p1'})
        assert o.output == 'text'
        assert o.port_id == 'p1'

    def test_from_jsonsable_raises_on_missing(self):
        o = CollectionModuleOutput()
        with pytest.raises(Exception, match='Invalid collection module output'):
            o.from_jsonsable({'output': 'x'})  # missing port_id

    def test_remap_ids_updates_port_id(self):
        o = CollectionModuleOutput(parent_id='mod-old')
        o.port_id = 'old-p'
        o.remap_ids({'mod-old': 'mod-new', 'old-p': 'new-p'})
        assert o.port_id == 'new-p'


# ===========================================================================
# Certificate
# ===========================================================================


class TestCertificate:
    def test_data_to_jsonable_full(self):
        c = Certificate()
        c.issuer = 'CN=DigiCert'
        c.issued = 100
        c.expires = 200
        c.fingerprint_hash = 'fp'
        c.domain_name_id_map = {'a.example.com': 'd1', 'b.example.com': 'd2'}
        d = c._data_to_jsonable()
        assert d['issuer'] == 'CN=DigiCert'
        assert d['issued'] == 100
        assert d['expires'] == 200
        assert d['fingerprint_hash'] == 'fp'
        assert sorted(d['domain_id_list']) == ['d1', 'd2']

    def test_from_jsonsable_loads_all_fields(self):
        c = Certificate()
        c.from_jsonsable({
            'issuer': 'X',
            'issued': '50',
            'expires': '150',
            'fingerprint_hash': 'h',
            'domain_id_list': ['d1', 'd2'],
        })
        assert c.issuer == 'X'
        assert c.issued == 50
        assert c.expires == 150
        assert c.fingerprint_hash == 'h'
        assert c.domain_id_list == ['d1', 'd2']

    def test_from_jsonsable_raises_on_missing(self):
        c = Certificate()
        with pytest.raises(Exception, match='Invalid certificate'):
            c.from_jsonsable({'issuer': 'X'})  # missing others

    def test_add_domain_filters_wildcards_and_ips_and_dedups(self):
        c = Certificate()
        # Wildcard → None
        assert c.add_domain('h1', '*.example.com', 'ti') is None
        # Bare IP → None
        assert c.add_domain('h1', '8.8.8.8', 'ti') is None
        # Real domain → Domain record
        d1 = c.add_domain('h1', 'first.example.com', 'ti')
        assert d1 is not None
        # Dup → None (already in map)
        d2 = c.add_domain('h1', 'first.example.com', 'ti')
        assert d2 is None

    def test_remap_ids_updates_domain_ids(self):
        c = Certificate(parent_id='port-old')
        c.domain_id_list = ['old-d1', 'unchanged']
        c.domain_name_id_map = {'a.example.com': 'old-d1'}
        c.remap_ids({'port-old': 'port-new', 'old-d1': 'new-d1'})
        assert 'new-d1' in c.domain_id_list
        assert 'unchanged' in c.domain_id_list
        assert c.domain_name_id_map['a.example.com'] == 'new-d1'


# ===========================================================================
# Credential
# ===========================================================================


class TestCredential:
    def test_data_to_jsonable(self):
        cr = Credential()
        cr.username = 'admin'
        cr.password = 'secret'
        cr.privileged = True
        d = cr._data_to_jsonable()
        assert d == {'username': 'admin', 'password': 'secret', 'privileged': True}

    def test_from_jsonsable_loads(self):
        cr = Credential()
        cr.from_jsonsable({'username': 'u', 'password': 'p', 'privileged': False})
        assert cr.username == 'u'
        assert cr.password == 'p'
        assert cr.privileged is False

    def test_from_jsonsable_privileged_defaults_false(self):
        cr = Credential()
        cr.from_jsonsable({'username': 'u', 'password': 'p'})
        assert cr.privileged is False

    def test_from_jsonsable_raises_on_missing(self):
        cr = Credential()
        with pytest.raises(Exception, match='Invalid credential'):
            cr.from_jsonsable({'username': 'u'})
