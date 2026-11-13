"""Tests for the concurrency and browser-recovery behaviour of webcap_scan.webcap_asyncio.

webcap itself is replaced with a scripted fake so the recovery paths can be
driven deterministically without Chrome.
"""

from __future__ import annotations

import asyncio
import json
import sys
import types

import pytest

# The autouse fixture below replaces asyncio.sleep; fakes that need to really
# yield for a moment use this.
_REAL_SLEEP = asyncio.sleep


class _FakeWebCapError(Exception):
    pass


class _FakeShot:
    status_code = 200
    title = 'fake title'
    blob = b'fake'


def _fake_webcap(monkeypatch, behave):
    """Install a fake ``webcap`` whose Browser.screenshot is ``behave(browser, url)``.

    Returns the list that collects every Browser the code under test creates.
    """
    instances = []

    class Browser:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.index = len(instances)
            self.orphaned_session = False
            self.is_alive = False
            # False makes every DevTools request time out, like a wedged Chrome
            self.responsive = True
            self.calls = 0
            self.cleanups = 0
            instances.append(self)

        async def start(self):
            self.is_alive = True

        async def stop(self):
            self.is_alive = False

        async def force_target_cleanup(self):
            self.cleanups += 1
            self.orphaned_session = False

        async def request(self, command, **params):
            if not self.is_alive:
                raise _FakeWebCapError('The browser has stopped')
            if not self.responsive:
                raise asyncio.TimeoutError()
            return {}

        async def screenshot(self, url):
            self.calls += 1
            return await behave(self, url)

    webcap_mod = types.ModuleType('webcap')
    webcap_mod.Browser = Browser
    errors_mod = types.ModuleType('webcap.errors')
    errors_mod.WebCapError = _FakeWebCapError
    webcap_mod.errors = errors_mod
    monkeypatch.setitem(sys.modules, 'webcap', webcap_mod)
    monkeypatch.setitem(sys.modules, 'webcap.errors', errors_mod)
    return instances


def _run(tmp_path, urls, args='--timeout 1'):
    from reverge_collector.webcap_scan import webcap_asyncio

    out = tmp_path / 'screenshots.json'
    future_map = dict.fromkeys(urls, (1, None, None, '/'))
    asyncio.run(webcap_asyncio(future_map, str(out), args))
    return [json.loads(line) for line in out.read_text().splitlines() if line.strip()]


def _urls(count):
    return [f'http://host{i}.test/' for i in range(count)]


@pytest.fixture(autouse=True)
def _no_restart_settle(monkeypatch):
    """Skip the post-restart settle sleep so the tests stay fast."""

    async def fast_sleep(delay, *args, **kwargs):
        await _REAL_SLEEP(0)

    monkeypatch.setattr(asyncio, 'sleep', fast_sleep)


# ===========================================================================
# Concurrency
# ===========================================================================


class _InFlight:
    """Records how many screenshots were running at the same moment."""

    def __init__(self):
        self.now = 0
        self.peak = 0

    async def behave(self, browser, url):
        self.now += 1
        self.peak = max(self.peak, self.now)
        await _REAL_SLEEP(0.01)
        self.now -= 1
        return _FakeShot()


def test_threads_option_sets_how_many_urls_run_at_once(tmp_path, monkeypatch):
    in_flight = _InFlight()
    instances = _fake_webcap(monkeypatch, in_flight.behave)

    urls = _urls(7)
    entries = _run(tmp_path, urls, '--timeout 1 --threads 3')

    assert in_flight.peak == 3
    assert sorted(e['url'] for e in entries) == sorted(urls)
    assert len(instances) == 1


def test_single_thread_runs_one_url_at_a_time(tmp_path, monkeypatch):
    in_flight = _InFlight()
    _fake_webcap(monkeypatch, in_flight.behave)

    urls = _urls(4)
    entries = _run(tmp_path, urls, '--timeout 1 --threads 1')

    assert in_flight.peak == 1
    assert [e['url'] for e in entries] == urls


def test_unexpected_error_on_one_url_does_not_stop_the_rest(tmp_path, monkeypatch):
    async def behave(browser, url):
        if 'host1.' in url:
            raise RuntimeError('boom')
        return _FakeShot()

    _fake_webcap(monkeypatch, behave)

    urls = _urls(4)
    entries = _run(tmp_path, urls, '--timeout 1 --threads 2')

    assert sorted(e['url'] for e in entries) == sorted(u for u in urls if 'host1.' not in u)


# ===========================================================================
# Dead browser
# ===========================================================================


def test_dead_browser_is_restarted_and_url_retried(tmp_path, monkeypatch):
    """A browser that died mid-scan is replaced at once; the URL is not lost."""

    async def behave(browser, url):
        if browser.index == 0:
            browser.is_alive = False
            raise _FakeWebCapError('The browser has stopped')
        return _FakeShot()

    instances = _fake_webcap(monkeypatch, behave)

    entries = _run(tmp_path, ['http://one.test/'])

    assert [e['url'] for e in entries] == ['http://one.test/']
    assert len(instances) == 2


def test_dead_browser_is_replaced_once_and_no_urls_are_lost(tmp_path, monkeypatch):
    """Every URL in flight when Chrome dies is retried, on a single replacement."""

    async def behave(browser, url):
        if not browser.is_alive:
            raise _FakeWebCapError('The browser has stopped')
        if browser.index == 0:
            # chrome exits right after delivering its first screenshot
            browser.is_alive = False
        return _FakeShot()

    instances = _fake_webcap(monkeypatch, behave)

    urls = _urls(6)
    entries = _run(tmp_path, urls, '--timeout 1 --threads 3')

    assert sorted(e['url'] for e in entries) == sorted(urls)
    assert len(instances) == 2


def test_url_that_keeps_killing_the_browser_is_given_up_on(tmp_path, monkeypatch):
    async def behave(browser, url):
        if 'host1.' in url:
            browser.is_alive = False
            raise _FakeWebCapError('The browser has stopped')
        if not browser.is_alive:
            raise _FakeWebCapError('The browser has stopped')
        return _FakeShot()

    instances = _fake_webcap(monkeypatch, behave)

    urls = _urls(3)
    entries = _run(tmp_path, urls, '--timeout 1 --threads 1')

    assert [e['url'] for e in entries] == ['http://host0.test/', 'http://host2.test/']
    # it gets a second try on its own; killing that browser too settles it
    assert len(instances) == 3


def test_url_that_kills_the_browser_does_not_take_its_neighbours_with_it(tmp_path, monkeypatch):
    """URLs in flight alongside a browser-killer must still be captured."""

    async def behave(browser, url):
        await _REAL_SLEEP(0.01)
        if 'host2.' in url:
            browser.is_alive = False
        if not browser.is_alive:
            raise _FakeWebCapError('The browser has stopped')
        return _FakeShot()

    _fake_webcap(monkeypatch, behave)

    urls = _urls(9)
    entries = _run(tmp_path, urls, '--timeout 1 --threads 3')

    assert sorted(e['url'] for e in entries) == sorted(u for u in urls if 'host2.' not in u)


# ===========================================================================
# Failures on a browser that is still running
# ===========================================================================


def test_error_on_a_live_browser_is_retried_without_touching_other_tabs(tmp_path, monkeypatch):
    async def behave(browser, url):
        if browser.calls == 1:
            raise _FakeWebCapError('Error capturing screenshot')
        return _FakeShot()

    instances = _fake_webcap(monkeypatch, behave)

    entries = _run(tmp_path, ['http://one.test/'])

    assert [e['url'] for e in entries] == ['http://one.test/']
    assert len(instances) == 1
    # one failed URL says nothing about stray tabs
    assert instances[0].cleanups == 0


def test_run_of_dead_hosts_does_not_restart_a_healthy_browser(tmp_path, monkeypatch):
    """Hosts that don't answer are the hosts' problem, not Chrome's."""

    async def behave(browser, url):
        return None

    instances = _fake_webcap(monkeypatch, behave)

    entries = _run(tmp_path, _urls(12), '--timeout 1 --threads 2')

    assert entries == []
    assert len(instances) == 1
    # the pile-up of failures is still a reason to sweep for stray tabs
    assert instances[0].cleanups >= 1


def test_browser_that_stops_answering_is_restarted(tmp_path, monkeypatch):
    async def behave(browser, url):
        if browser.index == 0:
            browser.responsive = False
            return None
        return _FakeShot()

    instances = _fake_webcap(monkeypatch, behave)

    urls = _urls(8)
    entries = _run(tmp_path, urls, '--timeout 1 --threads 1')

    # five failures in a row trigger the health check, which finds it wedged
    assert [e['url'] for e in entries] == urls[5:]
    assert len(instances) == 2


def test_orphan_flag_triggers_a_stray_sweep(tmp_path, monkeypatch):
    async def behave(browser, url):
        if browser.calls == 1:
            browser.orphaned_session = True
        return _FakeShot()

    instances = _fake_webcap(monkeypatch, behave)

    entries = _run(tmp_path, _urls(3), '--timeout 1 --threads 1')

    assert len(entries) == 3
    assert instances[0].cleanups == 1
