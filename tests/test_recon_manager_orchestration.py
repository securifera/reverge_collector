"""Tests for ScheduledScanThread orchestration paths.

Covers the methods that run inside the polling/worker threads:
- _process_job_with_slot (CollectorJob lifecycle)
- process_collector_settings
- execute_scan_jobs (per-tool dispatch + status updates)
- process_scan_obj (top-level scan lifecycle + cleanup)

Each test builds a minimal ScheduledScanThread with a mocked
recon_manager and connection_manager so no network or threading is
involved.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from reverge_collector import data_model
from reverge_collector.recon_manager import ScheduledScanThread


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_thread(*, connection_manager=None, recon_manager=None):
    """Return a ScheduledScanThread that hasn't been started.

    threading.Thread.__init__ is cheap (no OS thread until .start()) so we
    use the real __init__ rather than patching it — tests then exercise
    real attribute setup."""
    rm = recon_manager if recon_manager is not None else MagicMock()
    cm = connection_manager  # may be None
    return ScheduledScanThread(rm, connection_manager=cm)


def make_job(job_id='job-1', target_id='target-1', job_type='shell', args=None):
    if args is None:
        args = '{"command": "echo hi"}'
    return SimpleNamespace(
        id=job_id,
        target_id=target_id,
        job_type=job_type,
        args=args,
    )


# ===========================================================================
# _process_job_with_slot
# ===========================================================================


class TestProcessJobWithSlot:
    def test_success_path_posts_completed_and_pops_map(self):
        t = make_thread()
        job = make_job()
        t.scheduled_scan_map[job.id] = job

        with patch(
            'reverge_collector.job_executor.run_job',
            return_value={'exit_code': 0, 'output_text': 'hi', 'output_type': 'text'},
        ):
            t._process_job_with_slot(job)

        # COMPLETED status was POSTed
        calls = t.recon_manager.update_job_status.call_args_list
        # Two calls: RUNNING then COMPLETED
        assert any(
            c.args[1] == data_model.ScanStatus.COMPLETED.value
            for c in calls
        )
        # Map cleaned up
        assert job.id not in t.scheduled_scan_map
        # No pending retries
        assert t.pending_job_completions == {}

    def test_running_status_post_failure_is_swallowed(self):
        """If the initial RUNNING status update fails (server down), the
        job should still run — we don't want a flaky server to block jobs."""
        t = make_thread()
        # First call (RUNNING) raises; second call (COMPLETED) succeeds
        t.recon_manager.update_job_status.side_effect = [
            Exception('server down'),
            True,
        ]

        job = make_job()
        with patch(
            'reverge_collector.job_executor.run_job',
            return_value={'exit_code': 0},
        ):
            t._process_job_with_slot(job)
        # Despite the first failure, COMPLETED was posted
        assert t.recon_manager.update_job_status.call_count == 2

    def test_completed_post_failure_queues_for_retry(self):
        t = make_thread()
        # RUNNING ok, COMPLETED fails
        t.recon_manager.update_job_status.side_effect = [
            True,
            Exception('500 internal error'),
        ]

        job = make_job()
        t.scheduled_scan_map[job.id] = job
        with patch(
            'reverge_collector.job_executor.run_job',
            return_value={'exit_code': 0, 'foo': 'bar'},
        ):
            t._process_job_with_slot(job)

        # Queued for retry
        assert job.id in t.pending_job_completions
        pending = t.pending_job_completions[job.id]
        assert pending['status'] == data_model.ScanStatus.COMPLETED.value
        assert pending['result'] == {'exit_code': 0, 'foo': 'bar'}
        # When the COMPLETED post fails we return early — scheduled_scan_map
        # entry is NOT popped (so the poll loop won't re-dispatch this job
        # while the retry is pending).
        assert job.id in t.scheduled_scan_map

    def test_run_job_exception_routes_to_error_status(self):
        t = make_thread()
        job = make_job()
        with patch(
            'reverge_collector.job_executor.run_job',
            side_effect=RuntimeError('handler crashed'),
        ):
            t._process_job_with_slot(job)

        calls = t.recon_manager.update_job_status.call_args_list
        # ERROR was posted
        assert any(
            c.args[1] == data_model.ScanStatus.ERROR.value
            for c in calls
        )

    def test_error_status_post_failure_queues_for_retry(self):
        t = make_thread()
        # RUNNING ok, ERROR post fails
        t.recon_manager.update_job_status.side_effect = [
            True,
            Exception('server unreachable'),
        ]
        job = make_job()
        with patch(
            'reverge_collector.job_executor.run_job',
            side_effect=RuntimeError('boom'),
        ):
            t._process_job_with_slot(job)

        # Queued with ERROR status
        assert job.id in t.pending_job_completions
        assert (
            t.pending_job_completions[job.id]['status']
            == data_model.ScanStatus.ERROR.value
        )

    def test_connect_to_extender_failure_raises_runtime_error(self):
        cm = MagicMock()
        cm.connect_to_extender.return_value = False
        t = make_thread(connection_manager=cm)
        job = make_job()
        # Should NOT raise; the wrapper catches all exceptions
        t._process_job_with_slot(job)
        # Should have posted ERROR
        calls = t.recon_manager.update_job_status.call_args_list
        assert any(
            c.args[1] == data_model.ScanStatus.ERROR.value for c in calls
        )

    def test_connect_to_target_failure_routes_to_error(self):
        cm = MagicMock()
        cm.connect_to_extender.return_value = True
        cm.connect_to_target.return_value = False
        t = make_thread(connection_manager=cm)
        job = make_job()
        t._process_job_with_slot(job)
        calls = t.recon_manager.update_job_status.call_args_list
        assert any(
            c.args[1] == data_model.ScanStatus.ERROR.value for c in calls
        )

    def test_connection_lock_released_in_finally(self):
        cm = MagicMock()
        cm.connect_to_extender.return_value = True
        cm.connect_to_target.return_value = True
        t = make_thread(connection_manager=cm)
        with patch(
            'reverge_collector.job_executor.run_job',
            return_value={'exit_code': 0},
        ):
            t._process_job_with_slot(make_job())
        cm.get_connection_lock.assert_called()
        cm.free_connection_lock.assert_called()


# ===========================================================================
# process_collector_settings
# ===========================================================================


class TestProcessCollectorSettings:
    def test_updates_checkin_interval_when_in_range(self):
        t = make_thread()
        assert t.checkin_interval == 30  # default
        t.process_collector_settings({'poll_interval': 60})
        assert t.checkin_interval == 60

    def test_ignores_out_of_range_poll_interval(self):
        t = make_thread()
        t.process_collector_settings({'poll_interval': 0})
        assert t.checkin_interval == 30
        t.process_collector_settings({'poll_interval': 99999})
        assert t.checkin_interval == 30

    def test_no_change_when_value_equals_current(self):
        t = make_thread()
        t.checkin_interval = 60
        t.process_collector_settings({'poll_interval': 60})
        assert t.checkin_interval == 60

    def test_ignores_settings_without_poll_interval(self):
        t = make_thread()
        t.process_collector_settings({'other_setting': 'value'})
        assert t.checkin_interval == 30

    def test_swallows_invalid_value_exception(self):
        t = make_thread()
        # Non-numeric value → int() raises → caught
        t.process_collector_settings({'poll_interval': 'abc'})
        assert t.checkin_interval == 30  # unchanged

    def test_empty_settings_dict_is_noop(self):
        t = make_thread()
        t.process_collector_settings({})
        assert t.checkin_interval == 30


# ===========================================================================
# execute_scan_jobs
# ===========================================================================


def make_collection_tool(
    *,
    name='nmap',
    scan_order=1,
    enabled=1,
    tool_type=2,
    args='',
    args_override=None,
    api_key=None,
    inst_id=None,
):
    tool = SimpleNamespace(
        id='tool-%s' % name,
        name=name,
        scan_order=scan_order,
        args=args,
        tool_type=tool_type,
    )
    ct_inst = SimpleNamespace(
        id=inst_id or ('ct-' + name),
        collection_tool=tool,
        enabled=enabled,
        args_override=args_override,
        api_key=api_key,
    )
    return ct_inst


def make_scheduled_scan(*, collection_tool_map=None, scan_id='scan-1'):
    """Minimal ScheduledScan with attribute hooks the orchestrator reads."""
    if collection_tool_map is None:
        collection_tool_map = {}
    return SimpleNamespace(
        id=scan_id,
        scan_id=scan_id,
        target_id='target-1',
        collection_tool_map=collection_tool_map,
        current_tool=None,
        current_tool_instance_id=None,
        current_tool_api_key=None,
        has_pending_imports=False,
        update_tool_status=MagicMock(),
        cleanup=MagicMock(),
    )


def _scan_status(*, scan_status=None, cancelled_tool_ids=None):
    if scan_status is None:
        scan_status = data_model.ScanStatus.RUNNING.value
    if cancelled_tool_ids is None:
        cancelled_tool_ids = []
    return SimpleNamespace(
        scan_status=scan_status,
        cancelled_tool_ids=cancelled_tool_ids,
    )


class TestExecuteScanJobs:
    def test_skips_tools_with_no_scan_order(self):
        ct = make_collection_tool(name='no-order', scan_order=None)
        scan = make_scheduled_scan(collection_tool_map={'ct1': ct})
        t = make_thread()
        t.recon_manager.get_scan_status.return_value = _scan_status()

        out = t.execute_scan_jobs(scan)
        # No tool ran → no error message
        assert out is None
        t.recon_manager.scan_func.assert_not_called()

    def test_skips_disabled_tools(self):
        ct = make_collection_tool(enabled=0)
        scan = make_scheduled_scan(collection_tool_map={'ct1': ct})
        t = make_thread()
        t.recon_manager.get_scan_status.return_value = _scan_status()
        out = t.execute_scan_jobs(scan)
        assert out is None
        t.recon_manager.scan_func.assert_not_called()

    def test_extender_connect_failure_returns_error_message(self):
        cm = MagicMock()
        cm.connect_to_extender.return_value = False
        t = make_thread(connection_manager=cm)
        scan = make_scheduled_scan(
            collection_tool_map={'ct1': make_collection_tool()}
        )
        out = t.execute_scan_jobs(scan)
        assert out == 'Failed connecting to extender'

    def test_cancelled_scan_short_circuits_with_cleanup(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        t = make_thread()
        t.recon_manager.get_scan_status.return_value = _scan_status(
            scan_status=data_model.ScanStatus.CANCELLED.value
        )
        scan = make_scheduled_scan(
            collection_tool_map={'ct1': make_collection_tool()}
        )
        out = t.execute_scan_jobs(scan)
        assert out == "Scan cancelled or doesn't exist"
        t.recon_manager.scan_func.assert_not_called()

    def test_cancelled_individual_tool_is_skipped(self):
        ct = make_collection_tool(inst_id='ct-skip-me')
        scan = make_scheduled_scan(collection_tool_map={'ct1': ct})
        t = make_thread()
        t.recon_manager.get_scan_status.return_value = _scan_status(
            cancelled_tool_ids=['ct-skip-me']
        )
        out = t.execute_scan_jobs(scan)
        # Tool skipped; scan_func never invoked
        t.recon_manager.scan_func.assert_not_called()

    def test_successful_scan_and_import_cleanup_called(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        ct = make_collection_tool()
        scan = make_scheduled_scan(collection_tool_map={'ct1': ct})
        t = make_thread()
        t.recon_manager.get_scan_status.return_value = _scan_status()
        t.recon_manager.scan_func.return_value = True
        t.recon_manager.import_func.return_value = True
        out = t.execute_scan_jobs(scan)
        assert out is None
        t.recon_manager.scan_func.assert_called_once_with(scan)
        t.recon_manager.import_func.assert_called_once_with(scan)
        # Tool status was updated to COMPLETED at the end
        last_status_call = scan.update_tool_status.call_args_list[-1]
        assert last_status_call.args[1] == data_model.CollectionToolStatus.COMPLETED.value

    def test_scan_func_failure_stops_loop_and_marks_error(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        ct1 = make_collection_tool(name='first', scan_order=1, inst_id='ct1')
        ct2 = make_collection_tool(name='second', scan_order=2, inst_id='ct2')
        scan = make_scheduled_scan(
            collection_tool_map={'a': ct1, 'b': ct2}
        )
        t = make_thread()
        t.recon_manager.get_scan_status.return_value = _scan_status()
        # First tool fails scan_func
        t.recon_manager.scan_func.return_value = False

        out = t.execute_scan_jobs(scan)
        # Only one tool tried — loop broke after error
        assert t.recon_manager.scan_func.call_count == 1
        # ERROR status was recorded
        any_error = any(
            c.args[1] == data_model.CollectionToolStatus.ERROR.value
            for c in scan.update_tool_status.call_args_list
        )
        assert any_error

    def test_import_failure_sets_pending_imports_and_breaks(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        ct = make_collection_tool()
        scan = make_scheduled_scan(collection_tool_map={'a': ct})
        t = make_thread()
        t.recon_manager.get_scan_status.return_value = _scan_status()
        t.recon_manager.scan_func.return_value = True
        t.recon_manager.import_func.return_value = False
        out = t.execute_scan_jobs(scan)
        # Pending-imports flag set so the scan keeps RUNNING for retry
        assert scan.has_pending_imports is True
        # Tool status reflects IMPORT_FAILED
        any_import_fail = any(
            c.args[1] == data_model.CollectionToolStatus.IMPORT_FAILED.value
            for c in scan.update_tool_status.call_args_list
        )
        assert any_import_fail

    def test_scan_func_exception_marked_as_error(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        ct = make_collection_tool()
        scan = make_scheduled_scan(collection_tool_map={'a': ct})
        t = make_thread()
        t.recon_manager.get_scan_status.return_value = _scan_status()
        t.recon_manager.scan_func.side_effect = RuntimeError('oops')
        out = t.execute_scan_jobs(scan)
        # Tool got an ERROR status update with the error message
        any_error = any(
            c.args[1] == data_model.CollectionToolStatus.ERROR.value
            for c in scan.update_tool_status.call_args_list
        )
        assert any_error

    def test_args_override_replaces_tool_args(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        ct = make_collection_tool(args='-default', args_override='-custom')
        scan = make_scheduled_scan(collection_tool_map={'a': ct})
        t = make_thread()
        t.recon_manager.get_scan_status.return_value = _scan_status()
        t.recon_manager.scan_func.return_value = True
        t.recon_manager.import_func.return_value = True
        t.execute_scan_jobs(scan)
        # Tool's args were overridden before scan_func was called
        assert ct.collection_tool.args == '-custom'

    def test_target_connect_failure_returns_error_for_active_tool(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        cm = MagicMock()
        cm.connect_to_extender.return_value = True
        cm.connect_to_target.return_value = False
        t = make_thread(connection_manager=cm)
        # tool_type=2 → active scanner → triggers connect_to_target
        ct = make_collection_tool(tool_type=2)
        scan = make_scheduled_scan(collection_tool_map={'a': ct})
        t.recon_manager.get_scan_status.return_value = _scan_status()
        out = t.execute_scan_jobs(scan)
        assert out == 'Failed connecting to target'

    def test_passive_tool_skips_connect_to_target(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cm = MagicMock()
        cm.connect_to_extender.return_value = True
        # connect_to_target shouldn't be called for tool_type != 2
        cm.connect_to_target.return_value = False
        t = make_thread(connection_manager=cm)
        ct = make_collection_tool(tool_type=1)  # passive
        scan = make_scheduled_scan(collection_tool_map={'a': ct})
        t.recon_manager.get_scan_status.return_value = _scan_status()
        t.recon_manager.scan_func.return_value = True
        t.recon_manager.import_func.return_value = True
        t.execute_scan_jobs(scan)
        cm.connect_to_target.assert_not_called()


# ===========================================================================
# process_scan_obj
# ===========================================================================


class TestProcessScanObj:
    def _scan(self, has_pending_imports=False):
        scan = SimpleNamespace(
            id='scan-x',
            scan_id='scan-x',
            target_id='target-1',
            collection_tool_map={},
            current_tool=None,
            current_tool_instance_id=None,
            current_tool_api_key=None,
            has_pending_imports=has_pending_imports,
            update_tool_status=MagicMock(),
            update_scan_status=MagicMock(),
            cleanup=MagicMock(),
            kill_scan_processes=MagicMock(),
        )
        return scan

    def test_success_path_updates_status_completed_and_cleans_up(self):
        t = make_thread()
        scan = self._scan()
        t.scheduled_scan_map[scan.id] = scan
        with patch.object(t, 'execute_scan_jobs', return_value=None):
            t.process_scan_obj(scan)
        # Status updated to COMPLETED
        scan.update_scan_status.assert_called_once_with(
            data_model.ScanStatus.COMPLETED.value
        )
        scan.cleanup.assert_called_once()
        # Map cleaned up
        assert scan.id not in t.scheduled_scan_map

    def test_pending_imports_keeps_scan_running_and_skips_cleanup(self):
        t = make_thread()
        scan = self._scan(has_pending_imports=True)
        t.scheduled_scan_map[scan.id] = scan
        with patch.object(t, 'execute_scan_jobs', return_value=None):
            t.process_scan_obj(scan)
        # Status stays RUNNING
        scan.update_scan_status.assert_called_once_with(
            data_model.ScanStatus.RUNNING.value
        )
        # No cleanup so output files survive for retry
        scan.cleanup.assert_not_called()

    def test_execute_scan_jobs_error_marks_scan_error(self):
        t = make_thread()
        scan = self._scan()
        t.scheduled_scan_map[scan.id] = scan
        with patch.object(t, 'execute_scan_jobs', return_value='something failed'):
            t.process_scan_obj(scan)
        scan.update_scan_status.assert_called_once_with(
            data_model.ScanStatus.ERROR.value
        )

    def test_outage_exception_marks_scan_cancelled(self):
        t = make_thread()
        scan = self._scan()
        t.scheduled_scan_map[scan.id] = scan
        with patch.object(
            t,
            'execute_scan_jobs',
            side_effect=RuntimeError('detected upstream outage during scan'),
        ):
            t.process_scan_obj(scan)
        scan.update_scan_status.assert_called_once_with(
            data_model.ScanStatus.CANCELLED.value
        )

    def test_scan_not_found_exception_removes_scan_from_map(self):
        from reverge_collector.recon_manager import ScanNotFoundException

        t = make_thread()
        scan = self._scan()
        t.scheduled_scan_map[scan.id] = scan
        scan.update_scan_status.side_effect = ScanNotFoundException('gone')

        with patch.object(t, 'execute_scan_jobs', return_value=None):
            t.process_scan_obj(scan)
        # Removed despite the exception
        assert scan.id not in t.scheduled_scan_map

    def test_map_cleaned_up_even_on_exception(self):
        t = make_thread()
        scan = self._scan()
        t.scheduled_scan_map[scan.id] = scan
        with patch.object(
            t, 'execute_scan_jobs', side_effect=ValueError('boom')
        ):
            t.process_scan_obj(scan)
        # Always popped at the end
        assert scan.id not in t.scheduled_scan_map
