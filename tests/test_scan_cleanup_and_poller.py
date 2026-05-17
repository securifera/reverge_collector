"""Tests for scan_cleanup and scan_poller — small orchestrator modules."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

# ===========================================================================
# scan_cleanup
# ===========================================================================


class TestScanCleanupFunc:
    def test_empty_scan_id_succeeds(self):
        from reverge_collector.scan_cleanup import scan_cleanup_func

        assert scan_cleanup_func('') is True
        assert scan_cleanup_func(None) is True

    def test_missing_directory_treated_as_success(self, tmp_path, monkeypatch):
        from reverge_collector.scan_cleanup import scan_cleanup_func

        monkeypatch.chdir(tmp_path)
        assert scan_cleanup_func('nonexistent-scan-id') is True

    def test_archives_existing_scan_dir(self, tmp_path, monkeypatch):
        from reverge_collector.scan_cleanup import scan_cleanup_func

        monkeypatch.chdir(tmp_path)
        scan_id = 'scan-abc'
        scan_dir = tmp_path / scan_id
        scan_dir.mkdir()
        (scan_dir / 'output.txt').write_text('some scanner output')
        (scan_dir / 'sub').mkdir()
        (scan_dir / 'sub' / 'inner.txt').write_text('nested')

        assert scan_cleanup_func(scan_id) is True

        # Source dir gone
        assert not scan_dir.exists()
        # Archive zip created
        archive_dir = tmp_path / 'archive'
        assert archive_dir.exists()
        zips = list(archive_dir.glob(f'{scan_id}_*.zip'))
        assert len(zips) == 1

    def test_creates_archive_dir_when_missing(self, tmp_path, monkeypatch):
        from reverge_collector.scan_cleanup import scan_cleanup_func

        monkeypatch.chdir(tmp_path)
        scan_id = 'fresh-scan'
        (tmp_path / scan_id).mkdir()
        (tmp_path / scan_id / 'data').write_text('x')

        # archive dir doesn't exist yet; function should create it
        assert not (tmp_path / 'archive').exists()
        assert scan_cleanup_func(scan_id) is True
        assert (tmp_path / 'archive').is_dir()

    def test_returns_false_on_archive_failure(self, tmp_path, monkeypatch):
        from reverge_collector import scan_cleanup

        monkeypatch.chdir(tmp_path)
        scan_id = 'broken-scan'
        (tmp_path / scan_id).mkdir()

        with patch.object(scan_cleanup.shutil, 'make_archive', side_effect=OSError('disk full')):
            assert scan_cleanup.scan_cleanup_func(scan_id) is False


# ===========================================================================
# scan_poller
# ===========================================================================


class TestPrintUsage:
    def test_print_usage_emits_help_lines(self, capsys):
        from reverge_collector.scan_poller import print_usage

        print_usage()
        captured = capsys.readouterr()
        assert 'Help:' in captured.out
        for cmd in (' q - quit', ' h - help', ' d - debug'):
            assert cmd in captured.out


class TestQueueHandler:
    def test_emits_formatted_record_to_queue(self):
        import logging
        import queue

        from reverge_collector.scan_poller import QueueHandler

        q = queue.Queue()
        h = QueueHandler(q)
        h.setLevel(logging.DEBUG)
        h.setFormatter(logging.Formatter('%(levelname)s:%(message)s'))

        record = logging.LogRecord(
            name='x',
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg='hello %s',
            args=('world',),
            exc_info=None,
        )
        h.emit(record)
        out = q.get_nowait()
        assert out == 'INFO:hello world'

    def test_emit_handles_queue_full(self):
        import logging
        import queue
        from unittest.mock import patch

        from reverge_collector.scan_poller import QueueHandler

        # queue with capacity 1, already full → put_nowait raises queue.Full
        q = queue.Queue(maxsize=1)
        q.put('existing')
        h = QueueHandler(q)
        record = logging.LogRecord(
            name='x',
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg='m',
            args=(),
            exc_info=None,
        )
        # Should call handleError but not raise
        with patch.object(h, 'handleError') as mock_handle:
            h.emit(record)
            mock_handle.assert_called_once_with(record)


class TestSetupLogging:
    def test_setup_logging_returns_queue_and_attaches_handler(self):
        import logging

        from reverge_collector.scan_poller import QueueHandler, setup_logging

        # Remember handlers so we can clean up
        root = logging.getLogger()
        original_handlers = list(root.handlers)
        original_level = root.level
        try:
            log_queue = setup_logging()
            queue_handlers = [h for h in root.handlers if isinstance(h, QueueHandler)]
            assert queue_handlers
            # setup_logging returns the queue object
            assert log_queue is queue_handlers[0].log_queue
        finally:
            root.handlers = original_handlers
            root.setLevel(original_level)
