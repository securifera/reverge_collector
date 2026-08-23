"""Tests for reverge_collector.job_executor — ad-hoc job dispatcher."""

from __future__ import annotations

import base64
import hashlib
import json
from unittest.mock import MagicMock, patch

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


def test_execute_shell_accepts_base64_command():
    cmd = 'echo from-b64-shell'
    out = job_executor.execute_shell({'command_b64': base64.b64encode(cmd.encode()).decode()})
    assert out['exit_code'] == 0
    assert 'from-b64-shell' in out['output_text']


def test_execute_shell_base64_takes_precedence_over_raw_command():
    out = job_executor.execute_shell(
        {
            'command': 'echo loser',
            'command_b64': base64.b64encode(b'echo winner').decode(),
        }
    )
    assert 'winner' in out['output_text']
    assert 'loser' not in out['output_text']


def test_execute_shell_bad_base64_returns_error():
    out = job_executor.execute_shell({'command_b64': 'not-valid-base64!!!'})
    assert out['exit_code'] == -1
    assert '[ERROR]' in out['output_text']


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


def test_execute_python_accepts_base64_script():
    script = 'print("from b64", 1 + 1)'
    out = job_executor.execute_python({'script_b64': base64.b64encode(script.encode()).decode()})
    assert out['exit_code'] == 0
    assert 'from b64 2' in out['output_text']


def test_execute_python_base64_takes_precedence_over_raw_script():
    script = 'print("winner")'
    out = job_executor.execute_python(
        {
            'script': 'print("loser")',
            'script_b64': base64.b64encode(script.encode()).decode(),
        }
    )
    assert 'winner' in out['output_text']
    assert 'loser' not in out['output_text']


def test_execute_python_bad_base64_returns_error():
    out = job_executor.execute_python({'script_b64': 'not-valid-base64!!!'})
    assert out['exit_code'] == -1
    assert '[ERROR]' in out['output_text']


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
# execute_http_request
# ---------------------------------------------------------------------------


def _fake_response(status_code=200, reason='OK', headers=None, text='', content=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.reason = reason
    resp.headers = headers or {'Content-Type': 'text/plain'}
    resp.text = text
    resp.content = content if content is not None else text.encode('utf-8')
    return resp


def test_execute_http_request_get_returns_status_and_body():
    with patch('reverge_collector.job_executor.requests.request') as m:
        m.return_value = _fake_response(
            200, 'OK', {'Content-Type': 'application/json'}, '{"ok":true}'
        )
        out = job_executor.execute_http_request({'url': 'http://example.com/api'})
    assert out['exit_code'] == 0
    assert out['output_type'] == 'text'
    assert 'HTTP 200 OK' in out['output_text']
    assert 'Content-Type: application/json' in out['output_text']
    assert '{"ok":true}' in out['output_text']
    # Defaults: GET method, no body
    args, kwargs = m.call_args
    assert kwargs['method'] == 'GET'
    assert kwargs['url'] == 'http://example.com/api'


def test_execute_http_request_passes_method_headers_body():
    with patch('reverge_collector.job_executor.requests.request') as m:
        m.return_value = _fake_response(201, 'Created')
        out = job_executor.execute_http_request(
            {
                'url': 'http://example.com/submit',
                'method': 'post',
                'headers': {'Authorization': 'Bearer t'},
                'body': 'payload',
            }
        )
    assert out['exit_code'] == 0
    _, kwargs = m.call_args
    assert kwargs['method'] == 'POST'  # normalized to upper
    assert kwargs['headers'] == {'Authorization': 'Bearer t'}
    assert kwargs['data'] == 'payload'


def test_execute_http_request_accepts_base64_body():
    raw = '{"weird": "quotes \\" and <xml attr=\'v\'/>"}'
    with patch('reverge_collector.job_executor.requests.request') as m:
        m.return_value = _fake_response(200, 'OK')
        out = job_executor.execute_http_request(
            {
                'url': 'http://example.com/submit',
                'method': 'POST',
                'body_b64': base64.b64encode(raw.encode()).decode(),
            }
        )
    assert out['exit_code'] == 0
    _, kwargs = m.call_args
    assert kwargs['data'] == raw.encode()


def test_execute_http_request_body_b64_takes_precedence_over_body():
    with patch('reverge_collector.job_executor.requests.request') as m:
        m.return_value = _fake_response(200, 'OK')
        job_executor.execute_http_request(
            {
                'url': 'http://example.com',
                'body': 'raw-loser',
                'body_b64': base64.b64encode(b'b64-winner').decode(),
            }
        )
    _, kwargs = m.call_args
    assert kwargs['data'] == b'b64-winner'


def test_execute_http_request_bad_body_b64_returns_error():
    out = job_executor.execute_http_request(
        {'url': 'http://example.com', 'body_b64': 'not-valid-base64!!!'}
    )
    assert out['exit_code'] == -1
    assert '[ERROR]' in out['output_text']


def test_execute_http_request_requires_url():
    out = job_executor.execute_http_request({})
    assert out['exit_code'] == -1
    assert 'url' in out['output_text'].lower()


def test_execute_http_request_non_2xx_still_succeeds():
    # A 404 is a completed request, not an executor failure.
    with patch('reverge_collector.job_executor.requests.request') as m:
        m.return_value = _fake_response(404, 'Not Found', text='nope')
        out = job_executor.execute_http_request({'url': 'http://example.com/missing'})
    assert out['exit_code'] == 0
    assert 'HTTP 404 Not Found' in out['output_text']


def test_execute_http_request_handles_connection_error():
    import requests as _requests

    with patch('reverge_collector.job_executor.requests.request') as m:
        m.side_effect = _requests.exceptions.ConnectionError('refused')
        out = job_executor.execute_http_request({'url': 'http://localhost:1/x'})
    assert out['exit_code'] == -1
    assert '[ERROR]' in out['output_text']


def test_execute_http_request_truncates_long_body():
    with patch('reverge_collector.job_executor.requests.request') as m:
        m.return_value = _fake_response(200, 'OK', text='x' * 100000)
        out = job_executor.execute_http_request({'url': 'http://example.com/big'})
    assert '[output truncated]' in out['output_text']
    assert len(out['output_text']) <= 65536 + 128


def test_execute_http_request_default_verify_and_timeout():
    with patch('reverge_collector.job_executor.requests.request') as m:
        m.return_value = _fake_response()
        job_executor.execute_http_request({'url': 'http://example.com'})
    _, kwargs = m.call_args
    assert kwargs['timeout'] == 30
    assert kwargs['verify'] is False


def test_run_job_dispatches_http_request():
    with patch('reverge_collector.job_executor.requests.request') as m:
        m.return_value = _fake_response(200, 'OK', text='hi')
        out = job_executor.run_job('http_request', {'url': 'http://example.com'})
    assert out['exit_code'] == 0
    assert 'HTTP 200 OK' in out['output_text']


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


# ---------------------------------------------------------------------------
# execute_file_download — binary safety, ranged reads, integrity
# ---------------------------------------------------------------------------


def _binary_blob(n=4096, seed=7):
    import random

    rnd = random.Random(seed)
    return b'PK\x03\x04' + bytes(rnd.getrandbits(8) for _ in range(n - 4))


def test_file_download_never_emits_replacement_characters(tmp_path):
    """Binary payloads must not be lossily decoded into output_text.

    A WAR/ZIP decoded with errors='replace' produces kilobytes of U+FFFD that
    look like the file's content to anything reading output_text — which is how
    a caller ends up with corrupted bytes while a perfectly good base64 blob
    sits unread in the same response.
    """
    data = _binary_blob()
    f = tmp_path / 'app.war'
    f.write_bytes(data)

    out = job_executor.execute_file_download({'remote_path': str(f)})
    assert out['exit_code'] == 0
    assert '�' not in out['output_text']
    assert base64.b64decode(out['output_blob_b64']) == data


def test_file_download_summarises_binary_instead_of_dumping_it(tmp_path):
    data = _binary_blob()
    f = tmp_path / 'app.war'
    f.write_bytes(data)

    out = job_executor.execute_file_download({'remote_path': str(f)})
    # The summary is metadata, not content — it must stay small.
    assert len(out['output_text']) < 512
    assert str(len(data)) in out['output_text']


def test_file_download_keeps_the_text_preview_for_utf8_files(tmp_path):
    f = tmp_path / 'notes.txt'
    f.write_text('hello world')
    out = job_executor.execute_file_download({'remote_path': str(f)})
    assert 'hello world' in out['output_text']


def test_file_download_reports_size_offset_and_eof(tmp_path):
    data = _binary_blob()
    f = tmp_path / 'app.war'
    f.write_bytes(data)

    out = job_executor.execute_file_download({'remote_path': str(f)})
    assert out['file_size'] == len(data)
    assert out['offset'] == 0
    assert out['bytes_returned'] == len(data)
    assert out['eof'] is True


def test_file_download_hashes_the_returned_chunk(tmp_path):
    data = _binary_blob()
    f = tmp_path / 'app.war'
    f.write_bytes(data)

    out = job_executor.execute_file_download({'remote_path': str(f)})
    assert out['sha256'] == hashlib.sha256(data).hexdigest()


def test_file_download_hashes_the_whole_file_when_the_chunk_covers_it(tmp_path):
    data = _binary_blob()
    f = tmp_path / 'app.war'
    f.write_bytes(data)

    out = job_executor.execute_file_download({'remote_path': str(f)})
    assert out['file_sha256'] == hashlib.sha256(data).hexdigest()


def test_file_download_reads_a_byte_range(tmp_path):
    data = _binary_blob()
    f = tmp_path / 'app.war'
    f.write_bytes(data)

    out = job_executor.execute_file_download({'remote_path': str(f), 'offset': 1000, 'length': 256})
    assert base64.b64decode(out['output_blob_b64']) == data[1000:1256]
    assert out['offset'] == 1000
    assert out['bytes_returned'] == 256
    assert out['eof'] is False
    assert out['next_offset'] == 1256


def test_file_download_chunks_reassemble_into_the_original(tmp_path):
    data = _binary_blob(n=5000)
    f = tmp_path / 'app.war'
    f.write_bytes(data)

    chunks, offset, guard = [], 0, 0
    while True:
        guard += 1
        assert guard < 100, 'chunk walk did not terminate'
        out = job_executor.execute_file_download(
            {'remote_path': str(f), 'offset': offset, 'length': 1024}
        )
        chunk = base64.b64decode(out['output_blob_b64'])
        assert out['sha256'] == hashlib.sha256(chunk).hexdigest()
        chunks.append(chunk)
        if out['eof']:
            break
        offset = out['next_offset']

    rebuilt = b''.join(chunks)
    assert rebuilt == data
    whole = job_executor.execute_file_download(
        {'remote_path': str(f), 'offset': 0, 'length': 0, 'include_file_sha256': True}
    )
    assert whole['file_sha256'] == hashlib.sha256(rebuilt).hexdigest()


def test_file_download_can_hash_the_whole_file_without_sending_it(tmp_path):
    data = _binary_blob(n=5000)
    f = tmp_path / 'app.war'
    f.write_bytes(data)

    out = job_executor.execute_file_download(
        {'remote_path': str(f), 'length': 0, 'include_file_sha256': True}
    )
    assert out['bytes_returned'] == 0
    assert out['output_blob_b64'] == ''
    assert out['file_sha256'] == hashlib.sha256(data).hexdigest()
    assert out['file_size'] == len(data)


def test_file_download_offset_past_eof_returns_empty_not_an_error(tmp_path):
    data = _binary_blob(n=100)
    f = tmp_path / 'app.war'
    f.write_bytes(data)

    out = job_executor.execute_file_download({'remote_path': str(f), 'offset': 999})
    assert out['exit_code'] == 0
    assert out['bytes_returned'] == 0
    assert out['eof'] is True


def test_file_download_rejects_a_negative_offset(tmp_path):
    f = tmp_path / 'app.war'
    f.write_bytes(b'abc')
    out = job_executor.execute_file_download({'remote_path': str(f), 'offset': -1})
    assert out['exit_code'] == -1
    assert '[ERROR]' in out['output_text']


def test_file_download_rejects_a_non_integer_offset(tmp_path):
    f = tmp_path / 'app.war'
    f.write_bytes(b'abc')
    out = job_executor.execute_file_download({'remote_path': str(f), 'offset': 'lots'})
    assert out['exit_code'] == -1
    assert '[ERROR]' in out['output_text']


def test_file_download_flags_truncation_instead_of_hiding_it(tmp_path, monkeypatch):
    # Reading up to a hard cap and returning it as though it were the whole
    # file hands the caller a silently truncated archive.
    monkeypatch.setattr(job_executor, '_MAX_DOWNLOAD_BYTES', 64)
    data = _binary_blob(n=512)
    f = tmp_path / 'app.war'
    f.write_bytes(data)

    out = job_executor.execute_file_download({'remote_path': str(f)})
    assert out['bytes_returned'] == 64
    assert out['eof'] is False
    assert out['file_size'] == 512
    assert out['next_offset'] == 64


def test_file_download_clamps_an_oversized_length(tmp_path, monkeypatch):
    monkeypatch.setattr(job_executor, '_MAX_DOWNLOAD_BYTES', 64)
    data = _binary_blob(n=512)
    f = tmp_path / 'app.war'
    f.write_bytes(data)

    out = job_executor.execute_file_download({'remote_path': str(f), 'length': 10_000})
    assert out['bytes_returned'] == 64
