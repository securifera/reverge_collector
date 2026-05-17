"""Tests for reverge_collector.proc_utils — process wrappers + stream reader."""

import io
import sys

from reverge_collector import proc_utils
from reverge_collector.proc_utils import ProcessStreamReader, process_wrapper

# ---------------------------------------------------------------------------
# ProcessStreamReader — drives off an in-memory BytesIO instead of a pipe
# ---------------------------------------------------------------------------


def test_stream_reader_collects_lines_from_pipe():
    """Lines pushed into the source pipe end up in get_output()."""
    pipe = io.BytesIO(b'first\nsecond\nthird\n')
    reader = ProcessStreamReader(
        ProcessStreamReader.StreamType.STDOUT, pipe, print_output=False, store_output=True
    )
    reader.start()
    reader.join(timeout=2)
    out = reader.get_output()
    assert out == 'first\nsecond\nthird\n'


def test_stream_reader_get_output_empty_when_no_lines():
    """An empty pipe → empty string."""
    pipe = io.BytesIO(b'')
    reader = ProcessStreamReader(
        ProcessStreamReader.StreamType.STDERR, pipe, print_output=False, store_output=True
    )
    reader.start()
    reader.join(timeout=2)
    assert reader.get_output() == ''


def test_stream_reader_marks_thread_daemon():
    """Stream readers should be daemons so they don't keep the process alive."""
    pipe = io.BytesIO(b'x')
    reader = ProcessStreamReader(
        ProcessStreamReader.StreamType.STDOUT, pipe, print_output=False, store_output=True
    )
    assert reader.daemon is True


def test_stream_reader_swallows_read_exception(monkeypatch):
    """If pipe.readline() raises mid-stream, the thread logs and finishes
    cleanly — it must not propagate the exception out of run()."""

    class BoomPipe:
        def readline(self):
            raise OSError('pipe broke')

    reader = ProcessStreamReader(
        ProcessStreamReader.StreamType.STDOUT, BoomPipe(), print_output=False, store_output=True
    )
    reader.start()
    reader.join(timeout=2)
    # Thread exited cleanly; output is empty (no data was queued before the
    # exception fired).
    assert reader.get_output() == ''


def test_stream_reader_print_output_logs_each_line(caplog):
    """print_output=True → each line is logged at DEBUG."""
    import logging as _logging

    pipe = io.BytesIO(b'log-line-1\nlog-line-2\n')
    reader = ProcessStreamReader(
        ProcessStreamReader.StreamType.STDOUT, pipe, print_output=True, store_output=False
    )
    with caplog.at_level(_logging.DEBUG, logger='reverge_collector.proc_utils'):
        reader.start()
        reader.join(timeout=2)
    debug_text = '\n'.join(r.message for r in caplog.records)
    assert 'log-line-1' in debug_text
    assert 'log-line-2' in debug_text


# ---------------------------------------------------------------------------
# process_wrapper — uses real subprocess; runs trivial commands
# ---------------------------------------------------------------------------


def test_process_wrapper_captures_stdout():
    """A simple echo → stdout captured + zero exit code."""
    out = process_wrapper(['echo', 'hello'], store_output=True)
    assert out['exit_code'] == 0
    assert 'hello' in out['stdout']


def test_process_wrapper_captures_stderr():
    """sh -c 'echo err >&2' → stderr captured."""
    out = process_wrapper(['sh', '-c', 'echo err 1>&2'], store_output=True)
    assert out['exit_code'] == 0
    assert 'err' in out['stderr']


def test_process_wrapper_nonzero_exit_code_propagates():
    out = process_wrapper(['sh', '-c', 'exit 7'], store_output=False)
    assert out['exit_code'] == 7


def test_process_wrapper_stdin_data_is_consumed():
    """stdin_data is piped in; cat passes it through to stdout."""
    out = process_wrapper(['cat'], stdin_data='from-stdin', store_output=True)
    assert out['exit_code'] == 0
    assert 'from-stdin' in out['stdout']


def test_process_wrapper_writes_stdout_to_file(tmp_path):
    """stdout_file=... writes stdout to that path."""
    stdout_path = tmp_path / 'out.txt'
    process_wrapper(['echo', 'into-file'], store_output=False, stdout_file=str(stdout_path))
    assert 'into-file' in stdout_path.read_text()


def test_process_wrapper_writes_stderr_to_file(tmp_path):
    """stderr_file=... writes stderr to that path."""
    stderr_path = tmp_path / 'err.txt'
    process_wrapper(
        ['sh', '-c', 'echo to-stderr 1>&2'],
        store_output=False,
        stderr_file=str(stderr_path),
    )
    assert 'to-stderr' in stderr_path.read_text()


def test_process_wrapper_invokes_pid_callback():
    """pid_callback is called with a ToolExecutor whose proc_pids set has the pid."""
    captured = {}

    def cb(executor):
        captured['executor'] = executor

    process_wrapper(['echo', 'x'], store_output=False, pid_callback=cb)
    assert 'executor' in captured
    # ToolExecutor stores pids in process_handles; get_process_pids() unwraps.
    assert len(captured['executor'].get_process_pids()) >= 1


def test_process_wrapper_use_shell_runs_through_shell():
    """use_shell=True passes a string command to the shell."""
    out = process_wrapper(['echo $((1+2))'], use_shell=True, store_output=True)
    assert out['exit_code'] == 0
    assert '3' in out['stdout']
