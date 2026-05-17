"""Tests for the small testable helpers in recon_manager.py."""

from __future__ import annotations

from types import SimpleNamespace

import pytest


def test_session_exception_default_message():
    from reverge_collector.recon_manager import SessionException

    e = SessionException()
    assert isinstance(e, Exception)
    assert str(e)  # has some message


def test_session_exception_custom_message():
    from reverge_collector.recon_manager import SessionException

    e = SessionException('custom session error')
    assert 'custom session error' in str(e)


def test_scan_not_found_exception_default_message():
    from reverge_collector.recon_manager import ScanNotFoundException

    e = ScanNotFoundException()
    assert 'not found' in str(e).lower()


def test_scan_not_found_exception_custom_message():
    from reverge_collector.recon_manager import ScanNotFoundException

    e = ScanNotFoundException('Scan ID 123 missing')
    assert 'Scan ID 123 missing' in str(e)


class TestToolOrderCmp:
    def _make(self, order):
        # SimpleNamespace with .collection_tool.scan_order
        return SimpleNamespace(collection_tool=SimpleNamespace(scan_order=order))

    def test_none_scan_order_has_highest_priority_on_left(self):
        from reverge_collector.recon_manager import tool_order_cmp

        x = self._make(None)
        y = self._make(5)
        assert tool_order_cmp(x, y) == -1

    def test_none_scan_order_has_highest_priority_on_right(self):
        from reverge_collector.recon_manager import tool_order_cmp

        x = self._make(5)
        y = self._make(None)
        assert tool_order_cmp(x, y) == 1

    def test_lower_order_sorts_first(self):
        from reverge_collector.recon_manager import tool_order_cmp

        x = self._make(2)
        y = self._make(5)
        assert tool_order_cmp(x, y) == -1
        assert tool_order_cmp(y, x) == 1

    def test_equal_order_returns_zero(self):
        from reverge_collector.recon_manager import tool_order_cmp

        x = self._make(3)
        y = self._make(3)
        assert tool_order_cmp(x, y) == 0


def test_get_recon_manager_returns_singleton():
    """get_recon_manager caches and returns the same instance on subsequent calls."""
    from unittest.mock import patch

    from reverge_collector import recon_manager as rm

    # Reset the module-level singleton for a clean test
    original = rm.recon_mgr_inst
    try:
        rm.recon_mgr_inst = None
        # ReconManager.__init__ is heavy (registers with server, loads tools);
        # patch it to a no-op and patch register_with_server too.
        with (
            patch.object(rm.ReconManager, '__init__', return_value=None),
            patch.object(rm.ReconManager, 'register_with_server', return_value=None),
        ):
            m1 = rm.get_recon_manager('token1', 'https://example.com')
            m2 = rm.get_recon_manager('token2', 'https://other.com')
        # Same singleton instance
        assert m1 is m2
    finally:
        rm.recon_mgr_inst = original
