"""Tests for scan_poller.main interactive command loop."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


def _make_args():
    return SimpleNamespace(token='t', test=False)


class TestMainCommands:
    def test_q_exits_loop_cleanly(self):
        from reverge_collector import scan_poller

        rm = MagicMock()
        thread = MagicMock()
        with (
            patch.object(scan_poller.recon_manager, 'get_recon_manager',
                         return_value=rm),
            patch.object(scan_poller.recon_manager, 'ScheduledScanThread',
                         return_value=thread),
            patch('builtins.input', side_effect=['q']),
            patch.object(scan_poller.time, 'sleep'),
        ):
            scan_poller.main(_make_args())
        # Scan thread was started and stopped
        thread.start.assert_called_once()
        thread.stop.assert_called_once()

    def test_h_calls_print_usage(self):
        from reverge_collector import scan_poller

        rm = MagicMock()
        thread = MagicMock()
        with (
            patch.object(scan_poller.recon_manager, 'get_recon_manager',
                         return_value=rm),
            patch.object(scan_poller.recon_manager, 'ScheduledScanThread',
                         return_value=thread),
            patch('builtins.input', side_effect=['h', 'q']),
            patch.object(scan_poller, 'print_usage') as pu,
            patch.object(scan_poller.time, 'sleep'),
        ):
            scan_poller.main(_make_args())
        pu.assert_called_once()

    def test_d_toggles_debug_flag(self):
        from reverge_collector import scan_poller

        rm = MagicMock()
        thread = MagicMock()
        with (
            patch.object(scan_poller.recon_manager, 'get_recon_manager',
                         return_value=rm),
            patch.object(scan_poller.recon_manager, 'ScheduledScanThread',
                         return_value=thread),
            patch('builtins.input', side_effect=['d', 'd', 'q']),
            patch.object(scan_poller.time, 'sleep'),
        ):
            scan_poller.main(_make_args())
        # set_debug was called twice (toggle on, toggle off)
        assert rm.set_debug.call_count == 2
        # First call enables, second disables
        assert rm.set_debug.call_args_list[0][0][0] is True
        assert rm.set_debug.call_args_list[1][0][0] is False

    def test_x_toggles_poller(self):
        from reverge_collector import scan_poller

        rm = MagicMock()
        thread = MagicMock()
        with (
            patch.object(scan_poller.recon_manager, 'get_recon_manager',
                         return_value=rm),
            patch.object(scan_poller.recon_manager, 'ScheduledScanThread',
                         return_value=thread),
            patch('builtins.input', side_effect=['x', 'q']),
            patch.object(scan_poller.time, 'sleep'),
        ):
            scan_poller.main(_make_args())
        thread.toggle_poller.assert_called_once()

    def test_unknown_command_is_ignored_until_q(self):
        from reverge_collector import scan_poller

        rm = MagicMock()
        thread = MagicMock()
        with (
            patch.object(scan_poller.recon_manager, 'get_recon_manager',
                         return_value=rm),
            patch.object(scan_poller.recon_manager, 'ScheduledScanThread',
                         return_value=thread),
            patch('builtins.input', side_effect=['unknown', '', 'q']),
            patch.object(scan_poller.time, 'sleep'),
        ):
            scan_poller.main(_make_args())
        thread.toggle_poller.assert_not_called()


def test_print_usage_emits_strings(capsys):
    from reverge_collector import scan_poller

    scan_poller.print_usage()
    captured = capsys.readouterr()
    # Help text should mention each of the command letters
    for letter in ('q', 'h', 'd', 'x'):
        assert letter in captured.out
