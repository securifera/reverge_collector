"""Tests for ProcessHandle in reverge_collector.process_handle."""

import os
from concurrent.futures import Future

from reverge_collector.process_handle import ProcessHandle

# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_process_handle_defaults_all_none():
    """A bare ProcessHandle has no future, no pid, no cleanup callback."""
    h = ProcessHandle()
    assert h.future is None
    assert h.pid is None
    assert h.on_cleanup is None


# ---------------------------------------------------------------------------
# is_done
# ---------------------------------------------------------------------------


def test_is_done_returns_true_when_no_future():
    """No future attached → considered done."""
    h = ProcessHandle()
    assert h.is_done() is True


def test_is_done_returns_false_for_pending_future():
    fut = Future()
    h = ProcessHandle(future=fut)
    assert h.is_done() is False


def test_is_done_returns_true_for_completed_future():
    fut = Future()
    fut.set_result('ok')
    h = ProcessHandle(future=fut)
    assert h.is_done() is True


# ---------------------------------------------------------------------------
# is_pid_alive
# ---------------------------------------------------------------------------


def test_is_pid_alive_false_when_no_pid():
    h = ProcessHandle()
    assert h.is_pid_alive() is False


def test_is_pid_alive_true_for_current_process():
    """PID of current process should always be alive."""
    h = ProcessHandle(pid=os.getpid())
    assert h.is_pid_alive() is True


def test_is_pid_alive_false_for_nonexistent_pid():
    """A PID we know doesn't exist → False."""
    # PID 999999 is well above typical pid_max for most systems.
    h = ProcessHandle(pid=999999)
    assert h.is_pid_alive() is False


# ---------------------------------------------------------------------------
# add_done_callback
# ---------------------------------------------------------------------------


def test_add_done_callback_no_future_is_noop():
    """No future → callback isn't attached anywhere, doesn't raise."""
    called = []
    h = ProcessHandle()
    h.add_done_callback(lambda f: called.append(f))
    # Nothing to call; the callback simply never fires.
    assert called == []


def test_add_done_callback_attaches_to_future():
    """A future-backed handle fires the callback when the future completes."""
    fut = Future()
    h = ProcessHandle(future=fut)
    seen = []
    h.add_done_callback(lambda f: seen.append(f))
    fut.set_result(42)
    assert seen == [fut]


# ---------------------------------------------------------------------------
# kill
# ---------------------------------------------------------------------------


def test_kill_cancels_pending_future():
    fut = Future()
    h = ProcessHandle(future=fut)
    h.kill()
    assert fut.cancelled() is True


def test_kill_swallows_kill_exception_for_dead_pid():
    """Killing a non-existent PID raises OSError internally but kill() swallows."""
    h = ProcessHandle(pid=999999)
    # Should not raise.
    h.kill()


def test_kill_invokes_on_cleanup_callback():
    """The on_cleanup callback fires after the kill steps."""
    called = []

    def on_clean(handle):
        called.append(handle)

    h = ProcessHandle(on_cleanup=on_clean)
    h.kill()
    assert called == [h]


def test_kill_swallows_on_cleanup_exception():
    """An exception inside on_cleanup must not propagate out of kill()."""

    def bad_cleanup(handle):
        raise RuntimeError('boom')

    h = ProcessHandle(on_cleanup=bad_cleanup)
    # Must not raise.
    h.kill()


def test_kill_swallows_future_cancel_exception():
    """An exception from future.cancel() is swallowed."""

    class BadFuture:
        def cancel(self):
            raise RuntimeError('cancel failed')

        def done(self):
            return False

    h = ProcessHandle(future=BadFuture())
    # Must not raise.
    h.kill()
