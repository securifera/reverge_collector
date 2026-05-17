"""Tests for scan_poller.setup_logging, QueueHandler, and main loop guards."""

from __future__ import annotations

import logging
import queue
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


# ===========================================================================
# QueueHandler
# ===========================================================================


class TestQueueHandler:
    def test_emit_puts_formatted_record_in_queue(self):
        from reverge_collector.scan_poller import QueueHandler

        q = queue.Queue()
        h = QueueHandler(q)
        rec = logging.LogRecord(
            name='x', level=logging.INFO, pathname='', lineno=1,
            msg='hello %s', args=('world',), exc_info=None,
        )
        h.emit(rec)
        msg = q.get_nowait()
        assert 'hello world' in msg

    def test_emit_falls_back_to_handleError_when_queue_full(self):
        from reverge_collector.scan_poller import QueueHandler

        q = queue.Queue(maxsize=1)
        q.put('blocking-message')  # queue now full
        h = QueueHandler(q)
        rec = logging.LogRecord(
            name='x', level=logging.INFO, pathname='', lineno=1,
            msg='dropped', args=None, exc_info=None,
        )
        with patch.object(h, 'handleError') as he:
            h.emit(rec)
        he.assert_called_once_with(rec)


# ===========================================================================
# setup_logging
# ===========================================================================


def test_setup_logging_returns_queue_with_attached_handler():
    from reverge_collector.scan_poller import setup_logging, QueueHandler

    q = setup_logging()
    assert isinstance(q, queue.Queue)
    # The root logger should now have a QueueHandler
    root = logging.getLogger()
    assert any(isinstance(h, QueueHandler) for h in root.handlers)


def test_setup_logging_routes_messages_to_queue():
    from reverge_collector.scan_poller import setup_logging

    q = setup_logging()
    # Drain any pre-existing messages
    while not q.empty():
        q.get_nowait()
    logging.getLogger(__name__).warning('test-message-zzz')
    # Pop up to 5 messages looking for ours
    found = False
    for _ in range(20):
        if q.empty():
            break
        msg = q.get_nowait()
        if 'test-message-zzz' in msg:
            found = True
            break
    assert found


# ===========================================================================
# main() guards
# ===========================================================================


class TestMainGuards:
    def test_main_session_exception_retries(self):
        """When get_recon_manager raises SessionException, main should sleep
        and retry. We make the second call succeed-with-exit so the loop
        exits cleanly."""
        from reverge_collector import scan_poller

        # First call: raise SessionException → triggers retry branch
        # Second call: raise generic Exception that doesn't match "refused"
        #              → falls through to "else" → break
        from reverge_collector.recon_manager import SessionException

        call_count = [0]

        def _get_rm(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise SessionException('no session')
            raise RuntimeError('exit-now')

        with (
            patch.object(scan_poller.recon_manager, 'get_recon_manager', side_effect=_get_rm),
            patch.object(scan_poller.time, 'sleep'),
        ):
            scan_poller.main(SimpleNamespace(token='t', test=False))

        assert call_count[0] == 2

    def test_main_connection_refused_retries(self):
        from reverge_collector import scan_poller

        call_count = [0]

        def _get_rm(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise Exception('Connection refused by server')
            raise RuntimeError('not-recoverable')

        with (
            patch.object(scan_poller.recon_manager, 'get_recon_manager', side_effect=_get_rm),
            patch.object(scan_poller.time, 'sleep'),
        ):
            scan_poller.main(SimpleNamespace(token='t', test=False))

        assert call_count[0] == 2

    def test_main_unhandled_exception_breaks(self):
        from reverge_collector import scan_poller

        with (
            patch.object(
                scan_poller.recon_manager,
                'get_recon_manager',
                side_effect=ValueError('unrecoverable'),
            ),
            patch.object(scan_poller.time, 'sleep'),
        ):
            # Should not raise — caught and printed
            scan_poller.main(SimpleNamespace(token='t', test=False))
