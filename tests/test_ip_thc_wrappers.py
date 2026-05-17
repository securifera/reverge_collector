"""Tests for ip_thc_lookup.subdomain_request_wrapper and
reverse_dns_request_wrapper. Both helpers wrap http.client retry/error
branches that the route tests don't reach."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch


def _resp(status=200, body=b''):
    r = MagicMock()
    r.status = status
    r.read.return_value = body
    return r


# ===========================================================================
# subdomain_request_wrapper
# ===========================================================================


class TestSubdomainRequestWrapper:
    def test_success_returns_domains(self):
        from reverge_collector.ip_thc_lookup import subdomain_request_wrapper

        body = json.dumps(
            {
                'domains': [
                    {'domain': 'a.example.com'},
                    {'domain': 'b.example.com'},
                ]
            }
        ).encode()
        conn = MagicMock()
        conn.getresponse.return_value = _resp(200, body)
        with patch(
            'reverge_collector.ip_thc_lookup.http.client.HTTPSConnection', return_value=conn
        ):
            out = subdomain_request_wrapper('example.com')
        assert out['target'] == 'example.com'
        assert sorted(out['domains']) == ['a.example.com', 'b.example.com']

    def test_429_retries_then_succeeds(self):
        from reverge_collector.ip_thc_lookup import subdomain_request_wrapper

        responses = [
            _resp(429, b'rate-limit'),
            _resp(200, json.dumps({'domains': [{'domain': 'ok.example.com'}]}).encode()),
        ]
        conn = MagicMock()
        conn.getresponse.side_effect = responses
        with (
            patch('reverge_collector.ip_thc_lookup.http.client.HTTPSConnection', return_value=conn),
            patch('time.sleep'),
        ):
            out = subdomain_request_wrapper('example.com')
        assert 'ok.example.com' in out['domains']

    def test_500_retries_then_succeeds(self):
        from reverge_collector.ip_thc_lookup import subdomain_request_wrapper

        responses = [
            _resp(500, b'server-error'),
            _resp(200, json.dumps({'domains': []}).encode()),
        ]
        conn = MagicMock()
        conn.getresponse.side_effect = responses
        with (
            patch('reverge_collector.ip_thc_lookup.http.client.HTTPSConnection', return_value=conn),
            patch('time.sleep'),
        ):
            out = subdomain_request_wrapper('example.com')
        assert out['target'] == 'example.com'
        assert out['domains'] == []

    def test_406_returns_empty_target(self):
        from reverge_collector.ip_thc_lookup import subdomain_request_wrapper

        conn = MagicMock()
        conn.getresponse.return_value = _resp(406, b'not-acceptable')
        with patch(
            'reverge_collector.ip_thc_lookup.http.client.HTTPSConnection', return_value=conn
        ):
            out = subdomain_request_wrapper('example.com')
        assert out == {'target': 'example.com', 'domains': []}

    def test_non_200_raises_runtime_error(self):
        import pytest
        from reverge_collector.ip_thc_lookup import subdomain_request_wrapper

        conn = MagicMock()
        conn.getresponse.return_value = _resp(403, b'forbidden')
        with patch(
            'reverge_collector.ip_thc_lookup.http.client.HTTPSConnection', return_value=conn
        ):
            with pytest.raises(RuntimeError, match='Error getting IP THC output'):
                subdomain_request_wrapper('example.com')

    def test_non_200_with_undecodable_bytes_still_raises(self):
        import pytest
        from reverge_collector.ip_thc_lookup import subdomain_request_wrapper

        conn = MagicMock()
        # bytes that aren't valid utf-8 → str(data) fallback
        conn.getresponse.return_value = _resp(500, b'\xff\xfe\xfa')
        # status 500 actually retries forever, so use 503 (other non-200)
        conn.getresponse.return_value = _resp(503, b'\xff\xfe\xfa')
        with patch(
            'reverge_collector.ip_thc_lookup.http.client.HTTPSConnection', return_value=conn
        ):
            with pytest.raises(RuntimeError):
                subdomain_request_wrapper('example.com')


# ===========================================================================
# reverse_dns_request_wrapper
# ===========================================================================


class TestReverseDnsWrapper:
    def test_success_returns_domains(self):
        from reverge_collector.ip_thc_lookup import reverse_dns_request_wrapper

        body = json.dumps(
            {
                'domains': [
                    {'domain': 'a.example.com'},
                    {'domain': 'b.example.com'},
                ]
            }
        ).encode()
        conn = MagicMock()
        conn.getresponse.return_value = _resp(200, body)
        with patch(
            'reverge_collector.ip_thc_lookup.http.client.HTTPSConnection', return_value=conn
        ):
            out = reverse_dns_request_wrapper('8.8.8.8')
        assert out['target'] == '8.8.8.8'
        assert 'a.example.com' in out['domains']

    def test_429_retries(self):
        from reverge_collector.ip_thc_lookup import reverse_dns_request_wrapper

        responses = [_resp(429), _resp(200, json.dumps({'domains': []}).encode())]
        conn = MagicMock()
        conn.getresponse.side_effect = responses
        with (
            patch('reverge_collector.ip_thc_lookup.http.client.HTTPSConnection', return_value=conn),
            patch('time.sleep'),
        ):
            out = reverse_dns_request_wrapper('8.8.8.8')
        assert out['target'] == '8.8.8.8'

    def test_406_returns_empty(self):
        from reverge_collector.ip_thc_lookup import reverse_dns_request_wrapper

        conn = MagicMock()
        conn.getresponse.return_value = _resp(406, b'na')
        with patch(
            'reverge_collector.ip_thc_lookup.http.client.HTTPSConnection', return_value=conn
        ):
            out = reverse_dns_request_wrapper('8.8.8.8')
        assert out == {'target': '8.8.8.8', 'domains': []}

    def test_non_200_raises(self):
        import pytest
        from reverge_collector.ip_thc_lookup import reverse_dns_request_wrapper

        conn = MagicMock()
        conn.getresponse.return_value = _resp(403, b'denied')
        with patch(
            'reverge_collector.ip_thc_lookup.http.client.HTTPSConnection', return_value=conn
        ):
            with pytest.raises(RuntimeError):
                reverse_dns_request_wrapper('8.8.8.8')


# ===========================================================================
# process_response edge cases
# ===========================================================================


class TestProcessResponse:
    def test_extracts_unique_domains(self):
        from reverge_collector.ip_thc_lookup import process_response

        body = json.dumps(
            {
                'domains': [
                    {'domain': 'a.example.com'},
                    {'domain': 'a.example.com'},
                    {'domain': 'b.example.com'},
                    # Non-dict entry skipped
                    'not-a-dict',
                    # Dict missing 'domain' key skipped
                    {'other': 'x'},
                ]
            }
        ).encode()
        out = process_response(body)
        assert out == {'a.example.com', 'b.example.com'}

    def test_returns_empty_when_not_dict(self):
        from reverge_collector.ip_thc_lookup import process_response

        body = json.dumps(['just', 'a', 'list']).encode()
        assert process_response(body) == set()

    def test_returns_empty_when_domains_not_list(self):
        from reverge_collector.ip_thc_lookup import process_response

        body = json.dumps({'domains': 'not-a-list'}).encode()
        assert process_response(body) == set()
