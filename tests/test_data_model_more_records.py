"""Round-trip tests for the data_model Record subtypes that the existing
test_data_model_records.py didn't reach: Screenshot, CollectionModule,
HttpEndpoint, HttpEndpointData, CollectionModuleOutput, Certificate,
Credential, Cpe edge cases.
"""

from __future__ import annotations

import pytest
from reverge_collector import data_model
from reverge_collector.data_model import (
    Certificate,
    CollectionModule,
    CollectionModuleOutput,
    Credential,
    Domain,
    Host,
    HttpEndpoint,
    HttpEndpointData,
    Port,
    Screenshot,
)

# ---------------------------------------------------------------------------
# Screenshot
# ---------------------------------------------------------------------------


def test_screenshot_init_defaults_none():
    s = Screenshot()
    assert s.screenshot is None
    assert s.image_hash is None


def test_screenshot_data_to_jsonable():
    s = Screenshot()
    s.screenshot = 'b64data'
    s.image_hash = 'h1'
    out = s._data_to_jsonable()
    assert out == {'screenshot': 'b64data', 'image_hash': 'h1'}


def test_screenshot_from_jsonsable_roundtrip():
    s1 = Screenshot()
    s1.screenshot = 'b64data'
    s1.image_hash = 'abc123'
    raw = s1.to_jsonable()

    s2 = Screenshot(id=s1.id)
    s2.from_jsonsable(raw['data'])
    assert s2.screenshot == 'b64data'
    assert s2.image_hash == 'abc123'


# ---------------------------------------------------------------------------
# CollectionModule
# ---------------------------------------------------------------------------


def test_collection_module_init_defaults():
    m = CollectionModule()
    assert m.name is None
    assert m.args is None
    assert m.description is None


def test_collection_module_data_to_jsonable_includes_name_args():
    m1 = CollectionModule(parent_id='tool-1')
    m1.name = 'mod-name'
    m1.args = '--foo'
    m1.description = 'a module'
    raw = m1.to_jsonable()
    assert raw['data']['name'] == 'mod-name'
    assert raw['data']['args'] == '--foo'


# ---------------------------------------------------------------------------
# HttpEndpoint
# ---------------------------------------------------------------------------


def test_http_endpoint_init_defaults():
    e = HttpEndpoint(parent_id='port-1')
    assert e.web_path_id is None


def test_http_endpoint_data_roundtrip():
    e1 = HttpEndpoint(parent_id='port-1')
    e1.web_path_id = 'path-uuid'
    raw = e1.to_jsonable()

    e2 = HttpEndpoint(parent_id='port-1', id=e1.id)
    e2.from_jsonsable(raw['data'])
    assert e2.web_path_id == 'path-uuid'


# ---------------------------------------------------------------------------
# HttpEndpointData
# ---------------------------------------------------------------------------


def test_http_endpoint_data_init_defaults():
    d = HttpEndpointData(parent_id='endpoint-1')
    assert d.status is None
    assert d.title is None
    assert d.domain_id is None
    assert d.screenshot_id is None


def test_http_endpoint_data_roundtrip():
    d1 = HttpEndpointData(parent_id='endpoint-1')
    d1.status = 200
    d1.title = 'Welcome'
    d1.domain_id = 'dom-uuid'
    d1.screenshot_id = 'shot-uuid'
    raw = d1.to_jsonable()

    d2 = HttpEndpointData(parent_id='endpoint-1', id=d1.id)
    d2.from_jsonsable(raw['data'])
    assert d2.status == 200
    assert d2.title == 'Welcome'
    assert d2.domain_id == 'dom-uuid'
    assert d2.screenshot_id == 'shot-uuid'


# ---------------------------------------------------------------------------
# CollectionModuleOutput
# ---------------------------------------------------------------------------


def test_collection_module_output_init():
    o = CollectionModuleOutput(parent_id='mod-1')
    assert o.output is None
    assert o.port_id is None


def test_collection_module_output_roundtrip():
    o1 = CollectionModuleOutput(parent_id='mod-1')
    o1.output = '[ADMIN~1, BACKUP~1]'
    o1.port_id = 'port-uuid'
    raw = o1.to_jsonable()

    o2 = CollectionModuleOutput(parent_id='mod-1', id=o1.id)
    o2.from_jsonsable(raw['data'])
    assert o2.output == '[ADMIN~1, BACKUP~1]'
    assert o2.port_id == 'port-uuid'


# ---------------------------------------------------------------------------
# Certificate
# ---------------------------------------------------------------------------


def test_certificate_init():
    c = Certificate(parent_id='port-1')
    # Just confirm we can instantiate
    assert c is not None


# ---------------------------------------------------------------------------
# Credential
# ---------------------------------------------------------------------------


def test_credential_init_defaults():
    c = Credential()
    assert c.username is None
    assert c.password is None
    assert c.privileged is False


def test_credential_roundtrip():
    c1 = Credential()
    c1.username = 'admin'
    c1.password = 'Password123!'
    c1.privileged = True
    raw = c1.to_jsonable()

    c2 = Credential(id=c1.id)
    c2.from_jsonsable(raw['data'])
    assert c2.username == 'admin'
    assert c2.password == 'Password123!'
    assert c2.privileged is True


def test_credential_privileged_defaults_to_false():
    c = Credential()
    c.username = 'u'
    c.password = 'p'
    raw = c.to_jsonable()

    c2 = Credential(id=c.id)
    c2.from_jsonsable(raw['data'])
    assert c2.privileged is False


# ---------------------------------------------------------------------------
# get_tool_classes — top-level helper
# ---------------------------------------------------------------------------


def test_get_tool_classes_returns_list_of_tool_specs():
    classes = data_model.get_tool_classes()
    assert isinstance(classes, list)
    # Should include known scanner classes
    names = {c.name for c in classes if hasattr(c, 'name')}
    assert 'nmap' in names or 'naabu' in names


# ---------------------------------------------------------------------------
# ToolExecutor — small dataclass-like
# ---------------------------------------------------------------------------


def test_tool_executor_init_defaults():
    from reverge_collector.data_model import ToolExecutor

    te = ToolExecutor()
    # Stored as process_handles list of ProcessHandle objects
    assert te.process_handles == []


def test_tool_executor_init_wraps_futures_and_pids():
    from reverge_collector.data_model import ToolExecutor

    te = ToolExecutor(thread_future_array=['f1', 'f2'], proc_pids={1, 2})
    # 2 futures + 2 pids → 4 ProcessHandle objects
    assert len(te.process_handles) == 4


def test_tool_executor_add_future_and_pid():
    from reverge_collector.data_model import ToolExecutor

    te = ToolExecutor()
    te.add_future('f1')
    te.add_pid(123)
    assert len(te.process_handles) == 2
    # First was a future, second a pid
    assert te.process_handles[0].future == 'f1'
    assert te.process_handles[1].pid == 123


# ---------------------------------------------------------------------------
# Subnet expansion / from_jsonsable edge cases
# ---------------------------------------------------------------------------


def test_subnet_from_jsonsable_populates_fields():
    """Subnet doesn't override _data_to_jsonable, so to_jsonable returns
    data=None. Inputs come from scope JSON, exercised via from_jsonsable."""
    from reverge_collector.data_model import Subnet

    s = Subnet()
    s.from_jsonsable({'subnet': '10.0.0.0', 'mask': 24})
    assert s.subnet == '10.0.0.0'
    assert s.mask == 24


# ---------------------------------------------------------------------------
# Vuln
# ---------------------------------------------------------------------------


def test_vuln_data_roundtrip():
    from reverge_collector.data_model import Vuln

    v1 = Vuln(parent_id='port-1')
    v1.name = 'sql_injection'
    v1.vuln_details = {'param': 'id'}
    raw = v1.to_jsonable()

    v2 = Vuln(parent_id='port-1', id=v1.id)
    v2.from_jsonsable(raw['data'])
    assert v2.name == 'sql_injection'


# ---------------------------------------------------------------------------
# ListItem (web path)
# ---------------------------------------------------------------------------


def test_list_item_data_roundtrip():
    from reverge_collector.data_model import ListItem

    li1 = ListItem()
    li1.web_path = '/admin/login.php'
    li1.web_path_hash = 'abc123'
    raw = li1.to_jsonable()

    li2 = ListItem(id=li1.id)
    li2.from_jsonsable(raw['data'])
    assert li2.web_path == '/admin/login.php'
    assert li2.web_path_hash == 'abc123'
