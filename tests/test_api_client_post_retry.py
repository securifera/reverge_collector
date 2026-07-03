"""Tests for the api_client._post retry / error branches and a few
endpoint-method paths that the existing api_client suite doesn't reach."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests
from reverge_collector.api_client import ApiClient

MANAGER_URL = 'http://test-server'
TOKEN = 'test-token'
SESSION_KEY = b'0' * 32


def _make_client():
    with patch.object(ApiClient, '_init_session_key', return_value=SESSION_KEY):
        return ApiClient(TOKEN, MANAGER_URL)


def _mock_resp(status, content=b'x'):
    r = MagicMock()
    r.status_code = status
    r.content = content
    r.json.return_value = {'data': 'enc'}
    return r


# ===========================================================================
# _post retry / failure paths
# ===========================================================================


class TestPostRetry:
    def test_connection_error_retries_then_raises_last(self):
        """All attempts hit ConnectionError → last_exc raised."""
        client = _make_client()
        with (
            patch.object(
                client._session,
                'post',
                side_effect=requests.ConnectionError('down'),
            ),
            patch('time.sleep'),
        ):
            with pytest.raises(requests.ConnectionError, match='down'):
                client._post('/x', {'a': 1})

    def test_timeout_retries_then_raises(self):
        client = _make_client()
        with (
            patch.object(
                client._session,
                'post',
                side_effect=requests.Timeout('slow'),
            ),
            patch('time.sleep'),
        ):
            with pytest.raises(requests.Timeout):
                client._post('/x', {'a': 1})

    def test_500_retries_then_raises_runtime(self):
        client = _make_client()
        with (
            patch.object(
                client._session,
                'post',
                return_value=_mock_resp(500),
            ),
            patch('time.sleep'),
        ):
            with pytest.raises(RuntimeError, match='HTTP 500'):
                client._post('/x', {'a': 1})

    def test_non_2xx_4xx_raises_immediately(self):
        client = _make_client()
        with patch.object(
            client._session,
            'post',
            return_value=_mock_resp(403),
        ):
            with pytest.raises(RuntimeError, match='HTTP 403'):
                client._post('/x', {'a': 1})

    def test_404_returns_none(self):
        client = _make_client()
        with patch.object(
            client._session,
            'post',
            return_value=_mock_resp(404),
        ):
            assert client._post('/x', {'a': 1}) is None

    def test_200_no_response_expected_returns_true(self):
        client = _make_client()
        with patch.object(
            client._session,
            'post',
            return_value=_mock_resp(200),
        ):
            assert client._post('/x', {'a': 1}) is True

    def test_200_empty_body_when_response_expected_returns_none(self):
        client = _make_client()
        with patch.object(
            client._session,
            'post',
            return_value=_mock_resp(200, content=b''),
        ):
            assert client._post('/x', {'a': 1}, expect_response=True) is None

    def test_200_decrypt_fail_returns_none(self):
        """When _decrypt raises, the except path returns None."""
        client = _make_client()
        with (
            patch.object(
                client._session,
                'post',
                return_value=_mock_resp(200),
            ),
            patch.object(client, '_decrypt', side_effect=Exception('decrypt-fail')),
        ):
            assert client._post('/x', {}, expect_response=True) is None

    def test_200_decrypt_returns_none_returns_none(self):
        client = _make_client()
        with (
            patch.object(
                client._session,
                'post',
                return_value=_mock_resp(200),
            ),
            patch.object(client, '_decrypt', return_value=None),
        ):
            assert client._post('/x', {}, expect_response=True) is None

    def test_200_success_returns_parsed_json(self):
        client = _make_client()
        with (
            patch.object(
                client._session,
                'post',
                return_value=_mock_resp(200),
            ),
            patch.object(client, '_decrypt', return_value=b'{"key": "value"}'),
        ):
            out = client._post('/x', {}, expect_response=True)
        assert out == {'key': 'value'}

    def test_connection_error_first_then_success(self):
        """First attempt fails, second succeeds → returns True."""
        client = _make_client()
        responses = [
            requests.ConnectionError('first-fail'),
            _mock_resp(200),
        ]

        def _side(*a, **kw):
            r = responses.pop(0)
            if isinstance(r, Exception):
                raise r
            return r

        with (
            patch.object(client._session, 'post', side_effect=_side),
            patch('time.sleep'),
        ):
            assert client._post('/x', {}) is True


# ===========================================================================
# Connection pooling (session reuse)
# ===========================================================================


class TestConnectionPooling:
    def test_client_has_pooled_session(self):
        """The client owns a single requests.Session so connections are reused
        across requests instead of a fresh TCP+TLS handshake per call."""
        client = _make_client()
        assert isinstance(client._session, requests.Session)

    def test_post_goes_through_session(self):
        """_post issues its request via the pooled session, not the module-level
        requests.post (which would open a new connection every time)."""
        client = _make_client()
        with patch.object(client._session, 'post', return_value=_mock_resp(200)) as sp:
            assert client._post('/x', {'a': 1}) is True
        sp.assert_called_once()

    def test_get_goes_through_session(self):
        client = _make_client()
        with patch.object(client._session, 'get', return_value=_mock_resp(404)) as sg:
            assert client._get('/x') is None
        sg.assert_called_once()

    def test_session_adapter_pool_configured(self):
        """The mounted adapter keeps a real pool (maxsize > 1) so concurrent
        job threads share keep-alive connections."""
        client = _make_client()
        adapter = client._session.get_adapter('https://test-server')
        assert adapter._pool_maxsize > 1

    def test_reset_pool_replaces_session_and_closes_old(self):
        """reset_pool() drops all pooled connections (stale after a launchpoint
        switch) by closing the old session and mounting a fresh pooled one."""
        client = _make_client()
        old = client._session
        with patch.object(old, 'close') as old_close:
            client.reset_pool()
        old_close.assert_called_once()
        assert client._session is not old
        assert isinstance(client._session, requests.Session)
        adapter = client._session.get_adapter('https://test-server')
        assert adapter._pool_maxsize > 1


# ===========================================================================
# Endpoint methods
# ===========================================================================


class TestUpdateJobStatus:
    def test_update_job_status_calls_post(self):
        client = _make_client()
        with patch.object(client, '_post', return_value=True) as p:
            assert client.update_job_status('job-1', 2, 'msg', {'r': 1}) is True
        p.assert_called_once_with(
            '/api/collector/job/job-1/',
            {'status': 2, 'status_message': 'msg', 'result': {'r': 1}},
        )

    def test_update_job_status_omits_result_when_none(self):
        client = _make_client()
        with patch.object(client, '_post', return_value=True) as p:
            client.update_job_status('job-2', 3, 'done')
        payload = p.call_args.args[1]
        assert 'result' not in payload
        assert payload['status'] == 3


class TestUpdateJobsStatusBatch:
    def test_batch_posts_all_entries_in_one_request(self):
        client = _make_client()
        entries = [
            {'job_id': 'j1', 'status': 2, 'result': {'exit_code': 0}},
            {'job_id': 'j2', 'status': 3, 'status_message': 'boom'},
        ]
        with patch.object(client, '_post', return_value=True) as p:
            assert client.update_jobs_status_batch(entries) is True
        p.assert_called_once_with('/api/collector/jobs/status/', {'jobs': entries})
