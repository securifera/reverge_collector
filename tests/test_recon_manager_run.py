"""Tests for ScheduledScanThread.run() — the main poll loop.

Strategy: each test patches `recon_manager.get_scheduled_scans` (the
last network call inside the inner try) so it flips `_is_running` to
False after one iteration. That lets the loop run exactly once and exit.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from unittest.mock import call as unittest_call

import pytest
from reverge_collector.recon_manager import ScheduledScanThread


def make_thread(connection_manager=None, recon_manager=None):
    rm = recon_manager if recon_manager is not None else MagicMock()
    t = ScheduledScanThread(rm, connection_manager=connection_manager)
    # Run-loop tests use exit_event.wait(checkin_interval) between iterations.
    # Default 30s would make a 2-iteration test take 30s; force 0s so the
    # tests run in milliseconds.
    t.checkin_interval = 0
    return t


def _stop_after_first_iter(thread):
    """Return a side_effect that stops the loop after recording the call."""

    def _side(*args, **kwargs):
        thread._is_running = False
        return []

    return _side


# ===========================================================================
# Guards: run() returns immediately when preconditions don't hold
# ===========================================================================


def test_run_returns_immediately_if_already_running():
    t = make_thread()
    t._is_running = True
    # Should not enter the loop at all
    with patch.object(t.recon_manager, 'collector_poll') as m:
        t.run()
        m.assert_not_called()


def test_run_returns_immediately_if_no_recon_manager():
    t = make_thread()
    t.recon_manager = None
    # Should not crash
    t.run()
    assert t._is_running is False


# ===========================================================================
# Single iteration: happy path
# ===========================================================================


def test_run_polls_collector_and_processes_settings():
    t = make_thread()
    t.recon_manager.get_scheduled_scans.side_effect = _stop_after_first_iter(t)
    t.recon_manager.collector_poll.return_value = {'poll_interval': 45}

    t.run()
    # collector_poll was invoked
    t.recon_manager.collector_poll.assert_called_once()
    # Settings were applied
    assert t.checkin_interval == 45


def test_run_skips_settings_processing_when_collector_poll_empty():
    t = make_thread()
    t.recon_manager.get_scheduled_scans.side_effect = _stop_after_first_iter(t)
    t.recon_manager.collector_poll.return_value = None

    initial_interval = t.checkin_interval
    t.run()
    # Interval unchanged when collector_poll returns nothing
    assert t.checkin_interval == initial_interval


def test_run_skips_when_disabled():
    """When _enabled=False the body of the loop should be skipped."""
    t = make_thread()
    t._enabled = False
    # Need something to flip _is_running so we don't loop forever
    original_wait = t.exit_event.wait

    call_count = [0]

    def fake_wait(*a, **kw):
        call_count[0] += 1
        if call_count[0] >= 2:
            t._is_running = False
        return original_wait(0)

    with patch.object(t.exit_event, 'wait', side_effect=fake_wait):
        t.run()
    # collector_poll never called because _enabled is False
    t.recon_manager.collector_poll.assert_not_called()


# ===========================================================================
# Log forwarding
# ===========================================================================


def test_run_forwards_log_queue_to_collector_poll():
    import queue

    t = make_thread()
    t.log_queue = queue.Queue()
    t.log_queue.put('line 1')
    t.log_queue.put('line 2')
    t.recon_manager.get_scheduled_scans.side_effect = _stop_after_first_iter(t)
    t.recon_manager.collector_poll.return_value = None

    t.run()
    # collector_poll was called with the joined log lines
    args = t.recon_manager.collector_poll.call_args.args
    assert 'line 1' in args[0]
    assert 'line 2' in args[0]


def test_run_caps_log_lines_at_100():
    import queue

    t = make_thread()
    t.log_queue = queue.Queue()
    for i in range(150):
        t.log_queue.put(f'line {i}')
    t.recon_manager.get_scheduled_scans.side_effect = _stop_after_first_iter(t)
    t.recon_manager.collector_poll.return_value = None

    t.run()
    args = t.recon_manager.collector_poll.call_args.args
    # Only first 100 went through
    assert 'line 99' in args[0]
    assert 'line 100' not in args[0]


def test_run_passes_none_to_collector_poll_when_no_log_queue():
    t = make_thread()
    t.log_queue = None
    t.recon_manager.get_scheduled_scans.side_effect = _stop_after_first_iter(t)
    t.recon_manager.collector_poll.return_value = None

    t.run()
    t.recon_manager.collector_poll.assert_called_once_with(None)


# ===========================================================================
# New scan dispatch
# ===========================================================================


def test_run_creates_scheduled_scan_for_new_scan_id():
    t = make_thread()
    new_scan_data = SimpleNamespace(id='scan-new', _type='scan', target_id='target-new')
    t.recon_manager.collector_poll.return_value = None

    # First call returns one new scan, second stops the loop
    call_count = [0]

    def get_scans(*args, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return [new_scan_data]
        t._is_running = False
        return []

    t.recon_manager.get_scheduled_scans.side_effect = get_scans

    # Patch ScheduledScan to avoid real construction
    with (
        patch(
            'reverge_collector.recon_manager.data_model.ScheduledScan',
            return_value=MagicMock(id='scan-new'),
        ),
        patch('reverge_collector.recon_manager.Thread') as ThreadCls,
    ):
        # Make Thread() a no-op
        ThreadCls.return_value = MagicMock()
        t.run()

    # Scan was added to the map and a Thread was spawned
    assert 'scan-new' in t.scheduled_scan_map
    assert ThreadCls.called


def test_run_skips_already_known_scan_with_no_cancellation():
    """Scan already in map; status is RUNNING → no action besides status check."""
    from reverge_collector import data_model

    t = make_thread()
    existing = MagicMock(id='scan-existing', scan_id='scan-existing')
    t.scheduled_scan_map['scan-existing'] = existing
    t.recon_manager.collector_poll.return_value = None

    # Returned scan-existing once, then stop
    server_view = SimpleNamespace(id='scan-existing', _type='scan')
    status_obj = SimpleNamespace(
        scan_status=data_model.ScanStatus.RUNNING.value,
        cancelled_tool_ids=[],
    )
    t.recon_manager.get_scan_status.return_value = status_obj
    call = [0]

    def get_scans(*args, **kwargs):
        call[0] += 1
        if call[0] == 1:
            return [server_view]
        t._is_running = False
        return []

    t.recon_manager.get_scheduled_scans.side_effect = get_scans
    t.run()
    # No process kill — scan still in the map
    assert 'scan-existing' in t.scheduled_scan_map
    existing.kill_scan_processes.assert_not_called()


def test_run_kills_cancelled_scan_and_removes_from_map():
    from reverge_collector import data_model

    t = make_thread()
    existing = MagicMock(id='scan-existing', scan_id='scan-existing')
    t.scheduled_scan_map['scan-existing'] = existing
    t.recon_manager.collector_poll.return_value = None

    server_view = SimpleNamespace(id='scan-existing', _type='scan')
    status_obj = SimpleNamespace(
        scan_status=data_model.ScanStatus.CANCELLED.value,
        cancelled_tool_ids=[],
    )
    t.recon_manager.get_scan_status.return_value = status_obj
    call = [0]

    def get_scans(*args, **kwargs):
        call[0] += 1
        if call[0] == 1:
            return [server_view]
        t._is_running = False
        return []

    t.recon_manager.get_scheduled_scans.side_effect = get_scans
    t.run()
    existing.kill_scan_processes.assert_called()
    assert 'scan-existing' not in t.scheduled_scan_map


def test_run_kills_individual_cancelled_tools():
    """Per-tool cancellation: kill_scan_processes called with the cancelled list."""
    from reverge_collector import data_model

    t = make_thread()
    existing = MagicMock(id='scan-existing', scan_id='scan-existing')
    existing.killed_tool_ids = set()
    t.scheduled_scan_map['scan-existing'] = existing
    t.recon_manager.collector_poll.return_value = None

    server_view = SimpleNamespace(id='scan-existing', _type='scan')
    status_obj = SimpleNamespace(
        scan_status=data_model.ScanStatus.RUNNING.value,
        cancelled_tool_ids=['tool-a', 'tool-b'],
    )
    t.recon_manager.get_scan_status.return_value = status_obj
    call = [0]

    def get_scans(*args, **kwargs):
        call[0] += 1
        if call[0] == 1:
            return [server_view]
        t._is_running = False
        return []

    t.recon_manager.get_scheduled_scans.side_effect = get_scans
    t.run()
    existing.kill_scan_processes.assert_called_with(['tool-a', 'tool-b'])
    # Still in map (not a full scan cancellation)
    assert 'scan-existing' in t.scheduled_scan_map


def test_run_kills_cancelled_tools_only_once_across_polls():
    """The server keeps listing the same cancelled tool ids while the scan is
    RUNNING. We must kill each tool once, not re-kill (and re-log) it every
    poll iteration."""
    from reverge_collector import data_model

    t = make_thread()
    existing = MagicMock(id='scan-existing', scan_id='scan-existing')
    existing.killed_tool_ids = set()
    t.scheduled_scan_map['scan-existing'] = existing
    t.recon_manager.collector_poll.return_value = None

    server_view = SimpleNamespace(id='scan-existing', _type='scan')
    status_obj = SimpleNamespace(
        scan_status=data_model.ScanStatus.RUNNING.value,
        cancelled_tool_ids=['tool-a', 'tool-b'],
    )
    t.recon_manager.get_scan_status.return_value = status_obj
    call = [0]

    def get_scans(*args, **kwargs):
        call[0] += 1
        # Same cancelled ids returned on two consecutive polls.
        if call[0] <= 2:
            return [server_view]
        t._is_running = False
        return []

    t.recon_manager.get_scheduled_scans.side_effect = get_scans
    t.run()
    # Killed exactly once despite the ids appearing on both polls.
    existing.kill_scan_processes.assert_called_once_with(['tool-a', 'tool-b'])


def test_run_kills_newly_cancelled_tools_on_later_poll():
    """A tool cancelled in a later poll is still killed (only the already-killed
    ones are skipped)."""
    from reverge_collector import data_model

    t = make_thread()
    existing = MagicMock(id='scan-existing', scan_id='scan-existing')
    existing.killed_tool_ids = set()
    t.scheduled_scan_map['scan-existing'] = existing
    t.recon_manager.collector_poll.return_value = None

    server_view = SimpleNamespace(id='scan-existing', _type='scan')
    statuses = [
        SimpleNamespace(
            scan_status=data_model.ScanStatus.RUNNING.value,
            cancelled_tool_ids=['tool-a'],
        ),
        SimpleNamespace(
            scan_status=data_model.ScanStatus.RUNNING.value,
            cancelled_tool_ids=['tool-a', 'tool-b'],
        ),
    ]
    t.recon_manager.get_scan_status.side_effect = statuses
    call = [0]

    def get_scans(*args, **kwargs):
        call[0] += 1
        if call[0] <= 2:
            return [server_view]
        t._is_running = False
        return []

    t.recon_manager.get_scheduled_scans.side_effect = get_scans
    t.run()
    # First poll kills tool-a; second poll kills only the newly-cancelled tool-b.
    assert existing.kill_scan_processes.call_args_list == [
        unittest_call(['tool-a']),
        unittest_call(['tool-b']),
    ]


# ===========================================================================
# Job dispatch (item_type='job')
# ===========================================================================


def test_run_dispatches_new_job_via_process_job_with_slot():
    t = make_thread()
    new_job = SimpleNamespace(id='job-new', _type='job', target_id='target-new')
    t.recon_manager.collector_poll.return_value = None
    call = [0]

    def get_scans(*args, **kwargs):
        call[0] += 1
        if call[0] == 1:
            return [new_job]
        t._is_running = False
        return []

    t.recon_manager.get_scheduled_scans.side_effect = get_scans
    with patch('reverge_collector.recon_manager.Thread') as ThreadCls:
        ThreadCls.return_value = MagicMock()
        t.run()
    # Job tracked
    assert 'job-new' in t.scheduled_scan_map
    # Thread was created
    assert ThreadCls.called


def test_run_defers_different_target_work_while_target_active():
    # Two jobs on different targets in one poll: the first checks out its target
    # (switcher); the second targets a different one and must be deferred so it
    # doesn't switch the launchpoint out from under the first.
    t = make_thread()
    job_a = SimpleNamespace(id='job-a', _type='job', target_id='A')
    job_b = SimpleNamespace(id='job-b', _type='job', target_id='B')
    t.recon_manager.collector_poll.return_value = None
    call = [0]

    def get_scans(*args, **kwargs):
        call[0] += 1
        if call[0] == 1:
            return [job_a, job_b]
        t._is_running = False
        return []

    t.recon_manager.get_scheduled_scans.side_effect = get_scans
    with patch('reverge_collector.recon_manager.Thread') as ThreadCls:
        ThreadCls.return_value = MagicMock()
        t.run()
    # First admitted (switcher), second deferred (re-fetched next poll).
    assert 'job-a' in t.scheduled_scan_map
    assert 'job-b' not in t.scheduled_scan_map
    assert ThreadCls.call_count == 1
    # Dispatched as switcher.
    assert ThreadCls.call_args.kwargs['target'].args[-1] == 'switch'


def test_run_admits_same_target_peer():
    # A new job for the already-active, reachable target is admitted as a
    # concurrent peer.
    t = make_thread()
    t._active_target_id = 'A'
    t._active_worker_count = 1
    t._active_target_reachable = True
    job = SimpleNamespace(id='job-peer', _type='job', target_id='A')
    t.recon_manager.collector_poll.return_value = None
    call = [0]

    def get_scans(*args, **kwargs):
        call[0] += 1
        if call[0] == 1:
            return [job]
        t._is_running = False
        return []

    t.recon_manager.get_scheduled_scans.side_effect = get_scans
    with patch('reverge_collector.recon_manager.Thread') as ThreadCls:
        ThreadCls.return_value = MagicMock()
        t.run()
    assert 'job-peer' in t.scheduled_scan_map
    assert ThreadCls.call_args.kwargs['target'].args[-1] == 'join'
    assert t._active_worker_count == 2


# ===========================================================================
# Error paths
# ===========================================================================


def test_run_handles_connection_error_without_exiting():
    import requests

    t = make_thread()
    call = [0]

    def fake_poll(*args, **kwargs):
        call[0] += 1
        if call[0] == 1:
            raise requests.exceptions.ConnectionError('server down')
        t._is_running = False
        return None

    t.recon_manager.collector_poll.side_effect = fake_poll
    t.recon_manager.get_scheduled_scans.return_value = []

    # Should not raise
    t.run()
    # Loop iterated more than once → ConnectionError was caught
    assert call[0] >= 2


def test_run_handles_generic_exception_without_exiting():
    t = make_thread()
    call = [0]

    def fake_poll(*args, **kwargs):
        call[0] += 1
        if call[0] == 1:
            raise RuntimeError('unexpected boom')
        t._is_running = False
        return None

    t.recon_manager.collector_poll.side_effect = fake_poll
    t.recon_manager.get_scheduled_scans.return_value = []
    t.run()
    assert call[0] >= 2


def test_run_does_not_hold_connection_lock():
    # The poll loop no longer holds the connection lock — it only talks to the
    # server and dispatches workers. Holding it would block behind a long-running
    # switcher and stop same-target peers from ever being dispatched. The
    # target-affinity gate coordinates launchpoint use instead.
    cm = MagicMock()
    t = make_thread(connection_manager=cm)
    t.recon_manager.get_scheduled_scans.side_effect = _stop_after_first_iter(t)
    t.recon_manager.collector_poll.return_value = None
    t.run()
    cm.get_connection_lock.assert_not_called()
    cm.free_connection_lock.assert_not_called()


def test_run_handles_connection_error_with_connection_manager():
    """When ConnectionError fires with a connection_manager, the handler
    re-connects to extender (covers the if-branch in the except)."""
    import requests

    cm = MagicMock()
    t = make_thread(connection_manager=cm)
    call = [0]

    def fake_poll(*args, **kwargs):
        call[0] += 1
        if call[0] == 1:
            raise requests.exceptions.ConnectionError('server down')
        t._is_running = False
        return None

    t.recon_manager.collector_poll.side_effect = fake_poll
    t.recon_manager.get_scheduled_scans.return_value = []
    t.run()
    # connect_to_extender was called from inside the ConnectionError handler
    assert cm.connect_to_extender.called


# ===========================================================================
# Network-change barrier: the poll loop yields while the launchpoint switches
# ===========================================================================


def test_run_waits_for_network_before_polling():
    """A Synack launchpoint switch kills the route the manager tunnel rides on.

    The poll loop must wait for the connection manager to report the network
    settled before issuing a request, instead of firing one at a dead tunnel
    and blocking until the read timeout expires.
    """
    cm = MagicMock()
    order = []
    cm.wait_for_network.side_effect = lambda *a, **k: order.append('wait') or True
    t = make_thread(connection_manager=cm)
    t.recon_manager.collector_poll.side_effect = lambda *a, **k: order.append('poll')
    t.recon_manager.get_scheduled_scans.side_effect = _stop_after_first_iter(t)

    t.run()
    assert order == ['wait', 'poll']


def test_run_polls_anyway_when_network_wait_times_out():
    # A wedged barrier must never stop the loop permanently — a timed-out wait
    # falls through to the normal poll (which then drives its own recovery).
    cm = MagicMock()
    cm.wait_for_network.return_value = False
    t = make_thread(connection_manager=cm)
    t.recon_manager.get_scheduled_scans.side_effect = _stop_after_first_iter(t)
    t.run()
    t.recon_manager.collector_poll.assert_called_once()


def test_run_without_connection_manager_skips_network_wait():
    t = make_thread(connection_manager=None)
    t.recon_manager.get_scheduled_scans.side_effect = _stop_after_first_iter(t)
    t.run()
    t.recon_manager.collector_poll.assert_called_once()


def test_await_network_ready_survives_a_broken_barrier():
    cm = MagicMock()
    cm.wait_for_network.side_effect = RuntimeError('boom')
    t = make_thread(connection_manager=cm)
    assert t._await_network_ready() is True


# ===========================================================================
# Returning the launchpoint to the extender once work drains
# ===========================================================================


def test_run_restores_extender_after_target_work_drains():
    """The launchpoint must not stay parked on the last target.

    Workers only switch back when they need the server, so a target whose VPN
    still reaches the server was left connected indefinitely. The poll loop
    restores the extender once nothing is in flight.
    """
    cm = MagicMock()
    cm.connect_to_extender.return_value = True
    t = make_thread(connection_manager=cm)
    t._note_launchpoint_on_target()
    t.recon_manager.collector_poll.return_value = None
    t.recon_manager.get_scheduled_scans.side_effect = _stop_after_first_iter(t)

    t.run()
    cm.connect_to_extender.assert_called_once()
    assert t._launchpoint_on_target is False


def test_run_does_not_restore_extender_while_a_worker_is_in_flight():
    cm = MagicMock()
    t = make_thread(connection_manager=cm)
    t._note_launchpoint_on_target()
    t._admit_work('T')  # a worker owns the target
    t.recon_manager.collector_poll.return_value = None
    t.recon_manager.get_scheduled_scans.side_effect = _stop_after_first_iter(t)

    t.run()
    cm.connect_to_extender.assert_not_called()


def test_run_restores_extender_after_dispatching_nothing_new():
    # The restore runs after dispatch, so a poll that hands work out doesn't
    # bounce the launchpoint back and forth.
    cm = MagicMock()
    cm.connect_to_extender.return_value = True
    t = make_thread(connection_manager=cm)
    t._note_launchpoint_on_target()
    order = []
    t.recon_manager.collector_poll.side_effect = lambda *a, **k: order.append('poll')
    cm.connect_to_extender.side_effect = lambda *a, **k: order.append('restore') or True

    def scans(*args, **kwargs):
        t._is_running = False
        return []

    t.recon_manager.get_scheduled_scans.side_effect = scans
    t.run()
    assert order == ['poll', 'restore']
