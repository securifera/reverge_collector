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
    t = ScheduledScanThread(rm, connection_manager=cm)
    # Keep the reachability-confirm probe instant in tests (no real sleeps).
    t._target_reachable_confirm_delay = 0
    return t


def make_job(job_id='job-1', target_id='target-1', job_type='shell', args=None):
    if args is None:
        args = '{"command": "echo hi"}'
    return SimpleNamespace(
        id=job_id,
        target_id=target_id,
        job_type=job_type,
        args=args,
        _type='job',
    )


def _reported(recon_manager):
    """All (job_id, status) pairs reported via batched job-status calls."""
    pairs = []
    for c in recon_manager.update_jobs_status_batch.call_args_list:
        for entry in c.args[0]:
            pairs.append((entry['job_id'], entry['status']))
    return pairs


def _reported_statuses(recon_manager):
    """Just the reported status values (order preserved)."""
    return [s for _, s in _reported(recon_manager)]


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

        # COMPLETED status was reported (in the batch report).
        assert data_model.ScanStatus.COMPLETED.value in _reported_statuses(t.recon_manager)
        # Map cleaned up
        assert job.id not in t.scheduled_scan_map
        # No pending retries
        assert t.pending_job_completions == {}

    def test_launchpoint_switch_resets_api_pool(self):
        """After switching the launchpoint (connect_to_target / back to the
        extender), the pooled manager connections are stale for the new route,
        so the worker must reset the api_client pool before reporting."""
        cm = MagicMock()
        cm.connect_to_extender.return_value = True
        cm.connect_to_target.return_value = True
        t = make_thread(connection_manager=cm)
        job = make_job()
        t.scheduled_scan_map[job.id] = job

        with patch(
            'reverge_collector.job_executor.run_job',
            return_value={'exit_code': 0},
        ):
            t._process_job_with_slot(job)

        assert t.recon_manager.reset_api_pool.called

    def test_running_status_post_failure_is_swallowed(self):
        """If the initial RUNNING status update fails (server down), the
        job should still run — we don't want a flaky server to block jobs."""
        t = make_thread()
        # The RUNNING status update (per-job) fails.
        t.recon_manager.update_job_status.side_effect = Exception('server down')

        job = make_job()
        with patch(
            'reverge_collector.job_executor.run_job',
            return_value={'exit_code': 0},
        ):
            t._process_job_with_slot(job)
        # RUNNING was attempted, and despite its failure COMPLETED was still
        # reported (via the batch report).
        t.recon_manager.update_job_status.assert_called_once()
        assert data_model.ScanStatus.COMPLETED.value in _reported_statuses(t.recon_manager)

    def test_completed_post_failure_queues_for_retry(self):
        t = make_thread()
        # RUNNING ok (per-job), batch COMPLETED report fails.
        t.recon_manager.update_jobs_status_batch.side_effect = Exception('500 internal error')

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

        # ERROR was reported (in the batch report).
        assert data_model.ScanStatus.ERROR.value in _reported_statuses(t.recon_manager)

    def test_error_status_post_failure_queues_for_retry(self):
        t = make_thread()
        # RUNNING ok (per-job), batch ERROR report fails.
        t.recon_manager.update_jobs_status_batch.side_effect = Exception('server unreachable')
        job = make_job()
        with patch(
            'reverge_collector.job_executor.run_job',
            side_effect=RuntimeError('boom'),
        ):
            t._process_job_with_slot(job)

        # Queued with ERROR status
        assert job.id in t.pending_job_completions
        assert t.pending_job_completions[job.id]['status'] == data_model.ScanStatus.ERROR.value

    def test_connect_to_extender_failure_raises_runtime_error(self):
        cm = MagicMock()
        cm.connect_to_extender.return_value = False
        t = make_thread(connection_manager=cm)
        job = make_job()
        # Should NOT raise; the wrapper catches all exceptions
        t._process_job_with_slot(job)
        # Should have reported ERROR
        assert data_model.ScanStatus.ERROR.value in _reported_statuses(t.recon_manager)

    def test_connect_to_target_failure_routes_to_error(self):
        cm = MagicMock()
        cm.connect_to_extender.return_value = True
        cm.connect_to_target.return_value = False
        t = make_thread(connection_manager=cm)
        job = make_job()
        t._process_job_with_slot(job)
        assert data_model.ScanStatus.ERROR.value in _reported_statuses(t.recon_manager)

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
# _bucket_jobs_by_target + _process_job_batch_with_slot
# ===========================================================================


class TestBucketJobsByTarget:
    def test_groups_jobs_by_target_and_ignores_scans(self):
        t = make_thread()
        scan = SimpleNamespace(id='scan-1', target_id='target-A', _type='scan')
        items = [
            make_job('j1', target_id='target-A'),
            scan,
            make_job('j2', target_id='target-A'),
            make_job('j3', target_id='target-B'),
        ]
        buckets = t._bucket_jobs_by_target(items)
        assert [j.id for j in buckets['target-A']] == ['j1', 'j2']
        assert [j.id for j in buckets['target-B']] == ['j3']
        # Scans are not bucketed here.
        assert all(getattr(x, '_type', 'scan') == 'job' for v in buckets.values() for x in v)

    def test_skips_jobs_already_in_scheduled_map(self):
        t = make_thread()
        j1 = make_job('j1', target_id='target-A')
        j2 = make_job('j2', target_id='target-A')
        t.scheduled_scan_map['j1'] = j1  # already dispatched
        buckets = t._bucket_jobs_by_target([j1, j2])
        assert [j.id for j in buckets['target-A']] == ['j2']


class TestProcessJobBatchWithSlot:
    def test_batch_runs_all_jobs_with_single_target_switch(self):
        cm = MagicMock()
        cm.connect_to_extender.return_value = True
        cm.connect_to_target.return_value = True
        t = make_thread(connection_manager=cm)
        jobs = [make_job('j1'), make_job('j2'), make_job('j3')]
        for j in jobs:
            t.scheduled_scan_map[j.id] = j

        with patch(
            'reverge_collector.job_executor.run_job',
            return_value={'exit_code': 0},
        ) as rj:
            t._process_job_batch_with_slot(jobs, 'switch')

        # Exactly one launchpoint switch for the whole batch.
        assert cm.connect_to_target.call_count == 1
        # Every job ran.
        assert rj.call_count == 3
        # All three reported COMPLETED, in a single batched request.
        assert t.recon_manager.update_jobs_status_batch.call_count == 1
        statuses = _reported_statuses(t.recon_manager)
        assert statuses == [data_model.ScanStatus.COMPLETED.value] * 3
        # Every job removed from the in-flight map; one affinity slot released.
        assert t.scheduled_scan_map == {}

    def test_batch_slot_released_once_for_whole_batch(self):
        cm = MagicMock()
        cm.connect_to_extender.return_value = True
        cm.connect_to_target.return_value = True
        t = make_thread(connection_manager=cm)
        # Occupy the affinity gate as this batch's single slot.
        assert t._admit_work('target-1') == 'switch'
        jobs = [make_job('j1'), make_job('j2')]
        for j in jobs:
            t.scheduled_scan_map[j.id] = j
        with patch(
            'reverge_collector.job_executor.run_job',
            return_value={'exit_code': 0},
        ):
            t._process_job_batch_with_slot(jobs, 'switch')
        # The single slot drained → target released for the next poll.
        assert t._no_workers_in_flight()

    def test_batch_one_job_failure_does_not_abort_others(self):
        cm = MagicMock()
        cm.connect_to_extender.return_value = True
        cm.connect_to_target.return_value = True
        t = make_thread(connection_manager=cm)
        jobs = [make_job('j1'), make_job('j2'), make_job('j3')]
        for j in jobs:
            t.scheduled_scan_map[j.id] = j

        def _run(job_type, args):
            # Second job blows up; the others must still run + report.
            if 'boom' in args:
                raise RuntimeError('handler crashed')
            return {'exit_code': 0}

        jobs[1].args = 'boom'
        with patch('reverge_collector.job_executor.run_job', side_effect=_run):
            t._process_job_batch_with_slot(jobs, 'switch')

        statuses = _reported_statuses(t.recon_manager)
        assert statuses.count(data_model.ScanStatus.COMPLETED.value) == 2
        assert statuses.count(data_model.ScanStatus.ERROR.value) == 1
        assert t.scheduled_scan_map == {}


class TestDispatchJobBatches:
    def test_dispatches_first_target_and_defers_other_target(self):
        """Only one target can hold the launchpoint, so a poll admits the first
        target's whole batch and leaves the other target for the next poll."""
        t = make_thread()
        items = [
            make_job('j1', target_id='A'),
            make_job('j2', target_id='A'),
            make_job('j3', target_id='B'),
        ]
        with patch('reverge_collector.recon_manager.Thread') as MockThread:
            t._dispatch_job_batches(items)

        # One batch worker for the admitted target A; target B deferred.
        assert MockThread.call_count == 1
        p = MockThread.call_args.kwargs['target']
        assert p.func == t._process_job_batch_with_slot
        assert [j.id for j in p.args[0]] == ['j1', 'j2']
        assert p.args[1] == 'switch'
        # Only the admitted target's jobs are marked in-flight.
        assert set(t.scheduled_scan_map) == {'j1', 'j2'}
        MockThread.return_value.start.assert_called_once()

    def test_same_target_batch_joins_when_active_and_reachable(self):
        t = make_thread()
        assert t._admit_work('A') == 'switch'
        t._mark_target_reachable(True)
        with patch('reverge_collector.recon_manager.Thread') as MockThread:
            t._dispatch_job_batches([make_job('j9', target_id='A')])
        p = MockThread.call_args.kwargs['target']
        assert p.args[1] == 'join'

    def test_no_jobs_dispatches_nothing(self):
        t = make_thread()
        scan = SimpleNamespace(id='s1', target_id='A', _type='scan')
        with patch('reverge_collector.recon_manager.Thread') as MockThread:
            t._dispatch_job_batches([scan])
        MockThread.assert_not_called()
        assert t.scheduled_scan_map == {}


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
        scan = make_scheduled_scan(collection_tool_map={'ct1': make_collection_tool()})
        out = t.execute_scan_jobs(scan)
        assert out == 'Failed connecting to extender'

    def test_cancelled_scan_short_circuits_with_cleanup(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        t = make_thread()
        t.recon_manager.get_scan_status.return_value = _scan_status(
            scan_status=data_model.ScanStatus.CANCELLED.value
        )
        scan = make_scheduled_scan(collection_tool_map={'ct1': make_collection_tool()})
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
        scan = make_scheduled_scan(collection_tool_map={'a': ct1, 'b': ct2})
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

    def test_target_connect_failure_returns_error_for_active_tool(self, tmp_path, monkeypatch):
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
        scan.update_scan_status.assert_called_once_with(data_model.ScanStatus.COMPLETED.value)
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
        scan.update_scan_status.assert_called_once_with(data_model.ScanStatus.RUNNING.value)
        # No cleanup so output files survive for retry
        scan.cleanup.assert_not_called()

    def test_execute_scan_jobs_error_marks_scan_error(self):
        t = make_thread()
        scan = self._scan()
        t.scheduled_scan_map[scan.id] = scan
        with patch.object(t, 'execute_scan_jobs', return_value='something failed'):
            t.process_scan_obj(scan)
        scan.update_scan_status.assert_called_once_with(data_model.ScanStatus.ERROR.value)

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
        scan.update_scan_status.assert_called_once_with(data_model.ScanStatus.CANCELLED.value)

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
        with patch.object(t, 'execute_scan_jobs', side_effect=ValueError('boom')):
            t.process_scan_obj(scan)
        # Always popped at the end
        assert scan.id not in t.scheduled_scan_map

    def test_reachable_scan_takes_lock_but_skips_extender(self):
        # When the server is reachable from the target, the scan still takes the
        # connection lock and reports its status, but skips the costly switch
        # back to the extender — it reports directly over the target tunnel.
        cm = MagicMock()
        cm.is_server_reachable.return_value = True
        t = make_thread(connection_manager=cm)
        scan = self._scan()
        t.scheduled_scan_map[scan.id] = scan
        with patch.object(t, 'execute_scan_jobs', return_value=None):
            t.process_scan_obj(scan)
        cm.get_connection_lock.assert_called()
        cm.free_connection_lock.assert_called()
        cm.connect_to_extender.assert_not_called()
        # Still reports COMPLETED and cleans up
        scan.update_scan_status.assert_called_once_with(data_model.ScanStatus.COMPLETED.value)
        assert scan.id not in t.scheduled_scan_map

    def test_unreachable_scan_switches_back_to_extender(self):
        # When the server is NOT reachable from the target, the scan switches
        # the launchpoint back to the extender before reporting.
        cm = MagicMock()
        cm.is_server_reachable.return_value = False
        cm.connect_to_extender.return_value = True
        t = make_thread(connection_manager=cm)
        scan = self._scan()
        t.scheduled_scan_map[scan.id] = scan
        with patch.object(t, 'execute_scan_jobs', return_value=None):
            t.process_scan_obj(scan)
        cm.get_connection_lock.assert_called()
        cm.free_connection_lock.assert_called()
        cm.connect_to_extender.assert_called()
        scan.update_scan_status.assert_called_once_with(data_model.ScanStatus.COMPLETED.value)
        assert scan.id not in t.scheduled_scan_map


# ===========================================================================
# Connection dance: always connect to target, skip extender when reachable
# ===========================================================================


class TestServerReachableHelpers:
    """_server_reachable (safe probe) and _ensure_server_reachable (probe-or-switch)."""

    def test_server_reachable_none_cm(self):
        t = make_thread()
        assert t._server_reachable(None) is False

    def test_server_reachable_probe_missing(self):
        t = make_thread()
        assert t._server_reachable(SimpleNamespace()) is False

    def test_server_reachable_probe_true(self):
        cm = MagicMock()
        cm.is_server_reachable.return_value = True
        assert make_thread()._server_reachable(cm) is True

    def test_server_reachable_non_true_truthy(self):
        # Only a literal True counts (guards against a bare MagicMock return).
        cm = MagicMock()
        cm.is_server_reachable.return_value = 1
        assert make_thread()._server_reachable(cm) is False

    def test_server_reachable_probe_raises(self):
        cm = MagicMock()
        cm.is_server_reachable.side_effect = RuntimeError('boom')
        assert make_thread()._server_reachable(cm) is False

    def test_ensure_none_cm_is_true(self):
        assert make_thread()._ensure_server_reachable(None) is True

    def test_ensure_reachable_skips_extender(self):
        cm = MagicMock()
        cm.is_server_reachable.return_value = True
        assert make_thread()._ensure_server_reachable(cm) is True
        cm.connect_to_extender.assert_not_called()

    def test_ensure_unreachable_switches_to_extender(self):
        cm = MagicMock()
        cm.is_server_reachable.return_value = False
        cm.connect_to_extender.return_value = True
        assert make_thread()._ensure_server_reachable(cm) is True
        cm.connect_to_extender.assert_called_once()

    def test_ensure_extender_failure_returns_false(self):
        cm = MagicMock()
        cm.is_server_reachable.return_value = False
        cm.connect_to_extender.return_value = False
        assert make_thread()._ensure_server_reachable(cm) is False

    def test_ensure_unreachable_with_peers_does_not_switch(self):
        # When concurrent same-target peers are in flight (count > 1) a worker
        # that can't reach the server must NOT switch the launchpoint back to the
        # extender — that would yank the network out from under the peers. It
        # returns False so the caller queues the report for retry instead. The
        # reachable gate stays open so peers keep being admitted.
        cm = MagicMock()
        cm.is_server_reachable.return_value = False
        t = make_thread(connection_manager=cm)
        t._active_target_id = 'T'
        t._active_worker_count = 2  # a peer is also running
        t._active_target_reachable = True
        assert t._ensure_server_reachable(cm) is False
        cm.connect_to_extender.assert_not_called()
        assert t._active_target_reachable is True

    def test_ensure_unreachable_sole_holder_switches_and_closes_gate(self):
        # When the sole holder must fall back to the extender, the sole-holder
        # check and the gate-close must be atomic: it clears reachable BEFORE
        # switching so the poll loop can't admit a peer that would then run on
        # the wrong network.
        cm = MagicMock()
        cm.is_server_reachable.return_value = False
        cm.connect_to_extender.return_value = True
        t = make_thread(connection_manager=cm)
        t._active_target_id = 'T'
        t._active_worker_count = 1  # sole holder
        t._active_target_reachable = True
        assert t._ensure_server_reachable(cm) is True
        cm.connect_to_extender.assert_called_once()
        # Gate closed: a same-target admit now defers instead of joining.
        assert t._active_target_reachable is False
        assert t._admit_work('T') is None


# ===========================================================================
# Target-affinity gate (same-target concurrency, cross-target deferral)
# ===========================================================================


class TestTargetAffinityGate:
    def test_first_work_admitted_as_switcher(self):
        t = make_thread()
        assert t._admit_work('T') == 'switch'
        assert t._active_target_id == 'T'
        assert t._active_worker_count == 1
        # Not reachable until the switcher connects and confirms.
        assert t._active_target_reachable is False

    def test_same_target_deferred_until_reachable(self):
        t = make_thread()
        t._admit_work('T')  # switcher
        # Switcher hasn't confirmed reachability yet → peer is deferred.
        assert t._admit_work('T') is None
        assert t._active_worker_count == 1

    def test_same_target_peer_admitted_when_reachable(self):
        t = make_thread()
        t._admit_work('T')  # switcher
        t._mark_target_reachable(True)
        assert t._admit_work('T') == 'join'
        assert t._active_worker_count == 2

    def test_different_target_deferred(self):
        t = make_thread()
        t._admit_work('T')
        t._mark_target_reachable(True)
        # Different target must not switch while T is active.
        assert t._admit_work('OTHER') is None
        assert t._active_worker_count == 1
        assert t._active_target_id == 'T'

    def test_finish_work_resets_on_drain(self):
        t = make_thread()
        t._admit_work('T')
        t._mark_target_reachable(True)
        t._admit_work('T')  # peer, count == 2
        t._finish_work()
        assert t._active_worker_count == 1
        assert t._active_target_id == 'T'  # still active
        t._finish_work()
        assert t._active_worker_count == 0
        assert t._active_target_id is None
        assert t._active_target_reachable is False

    def test_after_drain_new_target_admitted(self):
        t = make_thread()
        t._admit_work('T')
        t._finish_work()
        assert t._admit_work('OTHER') == 'switch'
        assert t._active_target_id == 'OTHER'

    def test_finish_work_never_goes_negative(self):
        t = make_thread()
        t._finish_work()  # no admits — must not underflow
        assert t._active_worker_count == 0

    def test_try_begin_launchpoint_switch_sole_holder_closes_gate(self):
        t = make_thread()
        t._admit_work('T')  # count 1, switcher
        t._mark_target_reachable(True)
        # Sole holder → may switch, and the peer gate is closed atomically.
        assert t._try_begin_launchpoint_switch() is True
        assert t._active_target_reachable is False
        assert t._admit_work('T') is None  # no new peer admitted

    def test_try_begin_launchpoint_switch_blocked_by_peers(self):
        t = make_thread()
        t._admit_work('T')  # switcher
        t._mark_target_reachable(True)
        t._admit_work('T')  # peer, count 2
        # Peers present → may NOT switch, and the gate stays open.
        assert t._try_begin_launchpoint_switch() is False
        assert t._active_target_reachable is True


class TestJobConnectionDance:
    def test_reachable_job_connects_to_target_but_skips_extender(self):
        # Correctness: the job ALWAYS connects to the target so it runs on the
        # target network. Optimization: when the server is reachable from the
        # target it reports directly and skips the extender round-trip entirely.
        cm = MagicMock()
        cm.is_server_reachable.return_value = True
        cm.connect_to_target.return_value = True
        t = make_thread(connection_manager=cm)
        job = make_job()
        t.scheduled_scan_map[job.id] = job
        with patch(
            'reverge_collector.job_executor.run_job',
            return_value={'exit_code': 0},
        ):
            t._process_job_with_slot(job)
        cm.get_connection_lock.assert_called()
        cm.free_connection_lock.assert_called()
        cm.connect_to_target.assert_called()
        cm.connect_to_extender.assert_not_called()
        # Result still reported and map cleaned up.
        assert data_model.ScanStatus.COMPLETED.value in _reported_statuses(t.recon_manager)
        assert job.id not in t.scheduled_scan_map

    def test_unreachable_job_uses_serial_connection_dance(self):
        cm = MagicMock()
        cm.is_server_reachable.return_value = False
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
        cm.connect_to_extender.assert_called()
        cm.connect_to_target.assert_called()


class TestPeerJob:
    """A peer (mode='join') rides the launchpoint the switcher already committed
    to the target: no lock, no launchpoint switching, reports over the tunnel."""

    def test_peer_skips_lock_and_launchpoint(self):
        cm = MagicMock()
        t = make_thread(connection_manager=cm)
        # Simulate the gate having admitted a switcher + this peer.
        t._active_target_id = 'target-1'
        t._active_worker_count = 2
        t._active_target_reachable = True
        job = make_job()
        t.scheduled_scan_map[job.id] = job
        with patch(
            'reverge_collector.job_executor.run_job',
            return_value={'exit_code': 0},
        ):
            t._process_job_with_slot(job, mode='join')
        cm.get_connection_lock.assert_not_called()
        cm.free_connection_lock.assert_not_called()
        cm.connect_to_target.assert_not_called()
        cm.connect_to_extender.assert_not_called()
        # Still reports COMPLETED and cleans up.
        assert data_model.ScanStatus.COMPLETED.value in _reported_statuses(t.recon_manager)
        assert job.id not in t.scheduled_scan_map
        # Slot released (count back to switcher only).
        assert t._active_worker_count == 1

    def test_peer_completed_post_failure_queues_without_switching(self):
        cm = MagicMock()
        t = make_thread(connection_manager=cm)
        t._active_target_id = 'target-1'
        t._active_worker_count = 2
        t._active_target_reachable = True
        # RUNNING ok (per-job), batch COMPLETED report fails (server briefly
        # unreachable over the tunnel).
        t.recon_manager.update_jobs_status_batch.side_effect = Exception('500')
        job = make_job()
        t.scheduled_scan_map[job.id] = job
        with patch(
            'reverge_collector.job_executor.run_job',
            return_value={'exit_code': 0, 'foo': 'bar'},
        ):
            t._process_job_with_slot(job, mode='join')
        # Queued for retry, never switched the launchpoint.
        assert job.id in t.pending_job_completions
        cm.connect_to_extender.assert_not_called()
        assert job.id in t.scheduled_scan_map
        assert t._active_worker_count == 1


class TestScanConnectionDance:
    def test_reachable_scan_connects_to_target_but_skips_extender(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cm = MagicMock()
        cm.is_server_reachable.return_value = True
        cm.connect_to_target.return_value = True
        t = make_thread(connection_manager=cm)
        ct = make_collection_tool(tool_type=2)  # active scanner
        scan = make_scheduled_scan(collection_tool_map={'a': ct})
        t.recon_manager.get_scan_status.return_value = _scan_status()
        t.recon_manager.scan_func.return_value = True
        t.recon_manager.import_func.return_value = True
        out = t.execute_scan_jobs(scan)
        assert out is None
        cm.connect_to_target.assert_called()
        cm.connect_to_extender.assert_not_called()

    def test_unreachable_scan_connects_to_target_and_extender(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cm = MagicMock()
        cm.is_server_reachable.return_value = False
        cm.connect_to_extender.return_value = True
        cm.connect_to_target.return_value = True
        t = make_thread(connection_manager=cm)
        ct = make_collection_tool(tool_type=2)  # active scanner
        scan = make_scheduled_scan(collection_tool_map={'a': ct})
        t.recon_manager.get_scan_status.return_value = _scan_status()
        t.recon_manager.scan_func.return_value = True
        t.recon_manager.import_func.return_value = True
        out = t.execute_scan_jobs(scan)
        assert out is None
        cm.connect_to_target.assert_called()
        cm.connect_to_extender.assert_called()

    def test_peer_scan_runs_without_touching_launchpoint(self, tmp_path, monkeypatch):
        # A peer scan rides the launchpoint the switcher already committed to the
        # target: it never connects to target or extender, but still scans and
        # imports over the tunnel.
        monkeypatch.chdir(tmp_path)
        cm = MagicMock()
        # Even if reachability would say "switch", a peer must not.
        cm.is_server_reachable.return_value = False
        t = make_thread(connection_manager=cm)
        ct = make_collection_tool(tool_type=2)  # active scanner
        scan = make_scheduled_scan(collection_tool_map={'a': ct})
        t.recon_manager.get_scan_status.return_value = _scan_status()
        t.recon_manager.scan_func.return_value = True
        t.recon_manager.import_func.return_value = True
        out = t.execute_scan_jobs(scan, mode='join')
        assert out is None
        cm.connect_to_target.assert_not_called()
        cm.connect_to_extender.assert_not_called()
        # The scan still ran and imported.
        t.recon_manager.scan_func.assert_called()
        t.recon_manager.import_func.assert_called()
