"""Tests for the ToolSpec abstract base class in reverge_collector.tool_spec.

ToolSpec consolidates the boilerplate for tool implementations (idempotency,
input persistence, error wrapping). We test the concrete helpers + the
abstract interface contract via a minimal concrete subclass.
"""

import os
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from reverge_collector import data_model
from reverge_collector.tool_spec import ToolSpec

# ---------------------------------------------------------------------------
# A minimal concrete tool for exercising the base class helpers
# ---------------------------------------------------------------------------


class _StubTool(ToolSpec):
    """Concrete ToolSpec that records execute_scan/parse_output calls."""

    name = 'stub'
    description = 'test stub'
    scan_order = 1

    def __init__(self):
        super().__init__()
        self.execute_calls = []
        self.parse_calls = []
        self.fake_records = []

    def execute_scan(self, scan_input):
        self.execute_calls.append(scan_input)

    def parse_output(self, output_path, scan_input):
        self.parse_calls.append((output_path, scan_input))
        return self.fake_records


class _BrokenTool(ToolSpec):
    """Concrete ToolSpec that raises in execute_scan — for error paths."""

    name = 'broken'

    def execute_scan(self, scan_input):
        raise RuntimeError('intentional execute failure')

    def parse_output(self, output_path, scan_input):
        return []


# ---------------------------------------------------------------------------
# __init__ sets the four callable attrs to expected defaults
# ---------------------------------------------------------------------------


def test_tool_spec_init_binds_scan_func_to_run_scan():
    t = _StubTool()
    assert t.scan_func == t._run_scan


def test_tool_spec_init_binds_import_func_to_run_import():
    t = _StubTool()
    assert t.import_func == t._run_import


def test_tool_spec_init_default_modules_func_returns_empty_list():
    t = _StubTool()
    assert t.modules_func() == []


def test_tool_spec_init_default_scope_func_returns_false():
    t = _StubTool()
    assert t.scope_func() is False


# ---------------------------------------------------------------------------
# ToolSpec is abstract — can't instantiate without overriding the two methods
# ---------------------------------------------------------------------------


def test_tool_spec_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        ToolSpec()


def test_subclass_missing_parse_output_cannot_instantiate():
    class _PartialTool(ToolSpec):
        name = 'partial'

        def execute_scan(self, scan_input):
            pass

        # parse_output deliberately missing

    with pytest.raises(TypeError):
        _PartialTool()


# ---------------------------------------------------------------------------
# get_output_path — default naming pattern
# ---------------------------------------------------------------------------


def test_get_output_path_default_pattern(monkeypatch, tmp_path):
    """Default path is <init_tool_folder>/<tool>_outputs_<scan_id>."""
    t = _StubTool()
    scan_input = SimpleNamespace(id='scan-abc', current_tool=SimpleNamespace(name='stub'))

    def fake_init_folder(tool_name, kind, scan_id):
        return str(tmp_path / tool_name / kind / scan_id)

    with patch('reverge_collector.tool_spec.scan_utils.init_tool_folder', fake_init_folder):
        path = t.get_output_path(scan_input)

    assert path.endswith(f'stub{os.sep}outputs{os.sep}scan-abc{os.sep}stub_outputs_scan-abc')


# ---------------------------------------------------------------------------
# _run_scan — happy path + error path
# ---------------------------------------------------------------------------


def test_run_scan_calls_execute_scan_and_returns_true(tmp_path):
    t = _StubTool()
    scan_input = SimpleNamespace(
        id='s1',
        current_tool=SimpleNamespace(name='stub'),
        scan_data=SimpleNamespace(
            get_hosts=lambda: [],
            get_domains=lambda: [],
            host_port_obj_map={},
            get_port_number_list_from_scope=lambda: [],
            subnet_map={},
        ),
    )

    def fake_init_folder(tool_name, kind, scan_id):
        return str(tmp_path)

    with patch('reverge_collector.tool_spec.scan_utils.init_tool_folder', fake_init_folder):
        result = t._run_scan(scan_input)

    assert result is True
    assert t.execute_calls == [scan_input]


def test_run_scan_propagates_execute_scan_exception(tmp_path):
    """A failing execute_scan re-raises but logs first."""
    t = _BrokenTool()
    scan_input = SimpleNamespace(
        id='s1',
        current_tool=SimpleNamespace(name='broken'),
        scan_data=SimpleNamespace(
            get_hosts=lambda: [],
            get_domains=lambda: [],
            host_port_obj_map={},
            get_port_number_list_from_scope=lambda: [],
            subnet_map={},
        ),
    )

    def fake_init_folder(tool_name, kind, scan_id):
        return str(tmp_path)

    with patch('reverge_collector.tool_spec.scan_utils.init_tool_folder', fake_init_folder):
        with pytest.raises(RuntimeError, match='intentional execute failure'):
            t._run_scan(scan_input)


# ---------------------------------------------------------------------------
# _run_import — exists-check / already-done / pre-import retry paths
# ---------------------------------------------------------------------------


def test_run_import_returns_true_when_output_missing(tmp_path):
    """No output file on disk → import is a no-op success."""
    t = _StubTool()
    scan_input = SimpleNamespace(id='s1', current_tool=SimpleNamespace(name='stub'))
    nonexistent = str(tmp_path / 'never-written')
    with patch.object(t, 'get_output_path', return_value=nonexistent):
        result = t._run_import(scan_input)
    assert result is True
    assert t.parse_calls == []


def test_run_import_calls_parse_output_when_output_exists(tmp_path):
    """Output file exists, no already-done flag, no pre-import cache → parse."""
    t = _StubTool()
    scan_input = SimpleNamespace(id='s1', current_tool=SimpleNamespace(name='stub'))
    output_path = tmp_path / 'output.json'
    output_path.write_text('{}')
    with (
        patch.object(t, 'get_output_path', return_value=str(output_path)),
        patch('reverge_collector.tool_spec._import_already_done', return_value=False),
        patch('reverge_collector.tool_spec._load_pre_import_arr', return_value=None),
        patch('reverge_collector.tool_spec._import_results') as mock_import,
    ):
        result = t._run_import(scan_input)
    assert result is True
    assert len(t.parse_calls) == 1
    mock_import.assert_called_once()


def test_run_import_skips_parse_when_already_done(tmp_path):
    """import_already_done returns True → short-circuit, parse never called."""
    t = _StubTool()
    scan_input = SimpleNamespace(id='s1', current_tool=SimpleNamespace(name='stub'))
    output_path = tmp_path / 'output.json'
    output_path.write_text('{}')
    with (
        patch.object(t, 'get_output_path', return_value=str(output_path)),
        patch('reverge_collector.tool_spec._import_already_done', return_value=True),
    ):
        result = t._run_import(scan_input)
    assert result is True
    assert t.parse_calls == []


def test_run_import_uses_pre_import_cache_when_present(tmp_path):
    """Pre-import cache exists → re-POST without re-parsing."""
    t = _StubTool()
    scan_input = SimpleNamespace(id='s1', current_tool=SimpleNamespace(name='stub'))
    output_path = tmp_path / 'output.json'
    output_path.write_text('{}')
    cached_records = [{'id': 'r1'}, {'id': 'r2'}]
    with (
        patch.object(t, 'get_output_path', return_value=str(output_path)),
        patch('reverge_collector.tool_spec._import_already_done', return_value=False),
        patch(
            'reverge_collector.tool_spec._load_pre_import_arr',
            return_value=cached_records,
        ),
        patch('reverge_collector.tool_spec._post_pre_import') as mock_post,
    ):
        result = t._run_import(scan_input)
    assert result is True
    # Cached path bypasses parse_output entirely.
    assert t.parse_calls == []
    mock_post.assert_called_once_with(scan_input, cached_records, str(output_path))
