"""Tests for reverge_collector.job_executor — ad-hoc job dispatcher."""

from __future__ import annotations

import base64
import json
from unittest.mock import patch

import pytest
from reverge_collector import job_executor

# ---------------------------------------------------------------------------
# execute_shell
# ---------------------------------------------------------------------------


def test_execute_shell_captures_stdout():
    out = job_executor.execute_shell({'command': 'echo hello'})
    assert out['exit_code'] == 0
    assert 'hello' in out['output_text']
    assert out['output_type'] == 'text'


def test_execute_shell_captures_stderr_combined():
    out = job_executor.execute_shell({'command': 'echo err >&2'})
    assert 'err' in out['output_text']


def test_execute_shell_non_zero_exit():
    out = job_executor.execute_shell({'command': 'false'})
    assert out['exit_code'] != 0


def test_execute_shell_truncates_long_output():
    # _MAX_OUTPUT is 64KB; print 100KB
    out = job_executor.execute_shell({'command': 'python3 -c "print(\\"x\\" * 100000)"'})
    assert '[output truncated]' in out['output_text']
    # Truncated length is bounded
    assert len(out['output_text']) <= 65536 + 64


def test_execute_shell_empty_output_replaced():
    out = job_executor.execute_shell({'command': 'true'})
    assert out['output_text'] == '(no output)'


def test_execute_shell_handles_timeout():
    out = job_executor.execute_shell({'command': 'sleep 5', 'timeout': 1})
    assert out['exit_code'] == -1
    assert 'timed out' in out['output_text']


# ---------------------------------------------------------------------------
# execute_python
# ---------------------------------------------------------------------------


def test_execute_python_runs_inline_script():
    out = job_executor.execute_python({'script': 'print(2 + 2)'})
    assert out['exit_code'] == 0
    assert '4' in out['output_text']


def test_execute_python_captures_traceback():
    out = job_executor.execute_python({'script': 'raise RuntimeError("boom")'})
    # Python exits non-zero on uncaught exception
    assert out['exit_code'] != 0
    assert 'boom' in out['output_text']


def test_execute_python_timeout():
    out = job_executor.execute_python({'script': 'import time; time.sleep(10)', 'timeout': 1})
    assert out['exit_code'] == -1
    assert 'timed out' in out['output_text']


def test_execute_python_empty_output_replaced():
    out = job_executor.execute_python({'script': 'pass'})
    assert out['output_text'] == '(no output)'


# ---------------------------------------------------------------------------
# execute_file_upload / execute_file_download
# ---------------------------------------------------------------------------


def test_execute_file_upload_writes_binary(tmp_path):
    target = tmp_path / 'sub' / 'out.bin'
    content = b'\x00\x01\xff binary data'
    out = job_executor.execute_file_upload(
        {
            'remote_path': str(target),
            'content_b64': base64.b64encode(content).decode(),
        }
    )
    assert out['exit_code'] == 0
    assert target.exists()
    assert target.read_bytes() == content


def test_execute_file_upload_creates_parent_dirs(tmp_path):
    target = tmp_path / 'a' / 'b' / 'c' / 'file.txt'
    out = job_executor.execute_file_upload(
        {
            'remote_path': str(target),
            'content_b64': base64.b64encode(b'hello').decode(),
        }
    )
    assert out['exit_code'] == 0


def test_execute_file_upload_returns_error_on_bad_base64():
    out = job_executor.execute_file_upload(
        {'remote_path': '/tmp/x', 'content_b64': 'not-valid-base64!!!'}
    )
    assert out['exit_code'] == -1
    assert '[ERROR]' in out['output_text']


def test_execute_file_download_returns_b64_for_existing_file(tmp_path):
    f = tmp_path / 'r.txt'
    f.write_text('hello world')
    out = job_executor.execute_file_download({'remote_path': str(f)})
    assert out['exit_code'] == 0
    assert out['output_type'] == 'binary'
    assert base64.b64decode(out['output_blob_b64']) == b'hello world'
    assert 'hello world' in out['output_text']


def test_execute_file_download_handles_missing_file():
    out = job_executor.execute_file_download({'remote_path': '/this/does/not/exist.bin'})
    assert out['exit_code'] == -1
    assert 'file not found' in out['output_text']


def test_execute_file_download_handles_permission_error(tmp_path):
    # Create a file, then chmod to 000 so we can't read it; should hit
    # the generic Exception handler.
    f = tmp_path / 'noperm.txt'
    f.write_text('secret')
    import os

    os.chmod(f, 0)
    try:
        out = job_executor.execute_file_download({'remote_path': str(f)})
        # Either an error (if running as non-root) or success (if running
        # as root, who bypasses permissions). Both paths are valid.
        if out['exit_code'] != 0:
            assert '[ERROR]' in out['output_text']
    finally:
        os.chmod(f, 0o600)


# ---------------------------------------------------------------------------
# execute_directory_list
# ---------------------------------------------------------------------------


def test_execute_directory_list_lists_entries(tmp_path):
    (tmp_path / 'sub').mkdir()
    (tmp_path / 'f.txt').write_text('hi')
    out = job_executor.execute_directory_list({'path': str(tmp_path)})
    assert out['exit_code'] == 0
    assert '[d] sub' in out['output_text']
    assert '[f] f.txt' in out['output_text']
    assert 'bytes' in out['output_text']  # file size annotation


def test_execute_directory_list_empty(tmp_path):
    out = job_executor.execute_directory_list({'path': str(tmp_path)})
    assert out['output_text'] == '(empty directory)'


def test_execute_directory_list_missing_path():
    out = job_executor.execute_directory_list({'path': '/this/path/missing'})
    assert out['exit_code'] == -1
    assert 'directory not found' in out['output_text']


# ---------------------------------------------------------------------------
# run_job — dispatcher
# ---------------------------------------------------------------------------


def test_run_job_dispatches_shell():
    out = job_executor.run_job('shell', {'command': 'echo dispatch-test'})
    assert 'dispatch-test' in out['output_text']


def test_run_job_accepts_json_string():
    out = job_executor.run_job('shell', json.dumps({'command': 'echo from-json'}))
    assert 'from-json' in out['output_text']


def test_run_job_unknown_type():
    out = job_executor.run_job('not_a_real_type', {})
    assert out['exit_code'] == -1
    assert 'Unknown job_type' in out['output_text']
    # Should list valid types
    assert 'shell' in out['output_text']


def test_run_job_invalid_json_args():
    out = job_executor.run_job('shell', 'not json')
    assert out['exit_code'] == -1
    assert 'Invalid args JSON' in out['output_text']
