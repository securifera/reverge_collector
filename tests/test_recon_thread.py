"""Tests for ScheduledScanThread initialization, control, and pending-job
flush logic.

We patch threading.Thread.__init__ so the thread isn't actually started,
and supply a mock recon_manager so no network is touched.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


def _make_thread():
    """Construct a ScheduledScanThread with a real __init__ (threading.Thread
    is in-process and safe to instantiate without start())."""
    from reverge_collector.recon_manager import ScheduledScanThread

    rm = MagicMock()
    return ScheduledScanThread(rm, connection_manager=None)


def test_thread_init_sets_defaults():
    t = _make_thread()
    assert t._is_running is False
    assert t._enabled is True
    assert t.checkin_interval == 30
    assert t.scheduled_scan_map == {}
    assert t.failed_task_exception is None
    assert t.pending_job_completions == {}


def test_toggle_poller_flips_state():
    t = _make_thread()
    assert t._enabled is True
    t.toggle_poller()
    assert t._enabled is False
    t.toggle_poller()
    assert t._enabled is True


def test_catch_failure_records_tuple():
    t = _make_thread()
    task = MagicMock(name='task')
    err = RuntimeError('boom')
    t.catch_failure(task, err)
    assert t.failed_task_exception == (task, err)


def test_flush_pending_job_completions_clears_on_success():
    t = _make_thread()
    t.pending_job_completions = {'j1': {'status': 2, 'result': {'x': 1}, 'err_msg': None}}
    t.recon_manager.update_job_status.return_value = True

    t._flush_pending_job_completions()
    # Cleared on success
    assert t.pending_job_completions == {}
    t.recon_manager.update_job_status.assert_called_once_with(
        'j1', 2, status_message='', result={'x': 1}
    )


def test_flush_pending_job_completions_keeps_on_failure():
    t = _make_thread()
    t.pending_job_completions = {'j1': {'status': 2, 'result': None, 'err_msg': 'oops'}}
    t.recon_manager.update_job_status.side_effect = RuntimeError('server down')

    t._flush_pending_job_completions()
    # Still pending after a failed retry
    assert 'j1' in t.pending_job_completions


def test_process_scan_obj_with_slot_calls_process_scan_obj():
    t = _make_thread()
    fake_scan = MagicMock()
    with patch.object(t, 'process_scan_obj') as p:
        t._process_scan_obj_with_slot(fake_scan)
        p.assert_called_once_with(fake_scan)


def test_stop_signals_exit_event():
    t = _make_thread()
    # exit_event should not be set initially
    assert not t.exit_event.is_set()
    # stop() should set it
    with patch.object(t, 'join', return_value=None):  # don't actually join
        t.stop(timeout=0.1)
    assert t.exit_event.is_set()
