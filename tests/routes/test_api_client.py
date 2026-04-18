"""
Tests for reverge_collector.api_client.ApiClient

All tests mock the network layer (requests.get / requests.post) and the
encryption/decryption helpers so that no real server is required.
"""
import json
import pytest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from reverge_collector.api_client import ApiClient, ScheduledScanResponse
from reverge_collector.recon_manager import ScanNotFoundException


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MANAGER_URL = "http://test-server"
TOKEN = "test-token"
SESSION_KEY = b"0" * 32  # 32-byte dummy key


def _make_client():
    """Return an ApiClient with session-key init patched out."""
    with patch.object(ApiClient, "_init_session_key", return_value=SESSION_KEY):
        client = ApiClient(TOKEN, MANAGER_URL)
    return client


def _encrypted_response(payload):
    """
    Build a mock requests.Response whose .json() returns a {"data": ...} dict
    and whose ._decrypt() will return *payload* (via a patched _decrypt).
    """
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b"non-empty"
    mock_resp.json.return_value = {"data": "irrelevant_b64"}
    return mock_resp


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

class TestApiClientInit:

    def test_init_sets_manager_url(self):
        client = _make_client()
        assert client.manager_url == MANAGER_URL

    def test_init_sets_authorization_header(self):
        client = _make_client()
        assert client.headers["Authorization"] == "Bearer " + TOKEN

    def test_init_calls_init_session_key(self):
        with patch.object(ApiClient, "_init_session_key", return_value=SESSION_KEY) as mock_init:
            ApiClient(TOKEN, MANAGER_URL)
        mock_init.assert_called_once()

    def test_init_session_key_failure_raises(self):
        with patch.object(ApiClient, "_init_session_key", side_effect=RuntimeError("handshake failed")):
            with pytest.raises(RuntimeError):
                ApiClient(TOKEN, MANAGER_URL)


# ---------------------------------------------------------------------------
# _get helper
# ---------------------------------------------------------------------------

class TestGet:

    def setup_method(self):
        self.client = _make_client()

    def test_get_returns_none_on_404(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch("requests.get", return_value=mock_resp):
            result = self.client._get("/api/scheduler/")
        assert result is None

    def test_get_returns_none_on_non_200(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        with patch("requests.get", return_value=mock_resp):
            result = self.client._get("/api/scheduler/")
        assert result is None

    def test_get_returns_none_on_empty_content(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b""
        with patch("requests.get", return_value=mock_resp):
            result = self.client._get("/api/scheduler/")
        assert result is None

    def test_get_returns_decrypted_json(self):
        payload = {"key": "value"}
        mock_resp = _encrypted_response(payload)
        with patch("requests.get", return_value=mock_resp), \
                patch.object(self.client, "_decrypt", return_value=json.dumps(payload).encode()):
            result = self.client._get("/api/something")
        assert result == payload

    def test_get_as_namespace(self):
        payload = {"name": "scan1"}
        mock_resp = _encrypted_response(payload)
        with patch("requests.get", return_value=mock_resp), \
                patch.object(self.client, "_decrypt", return_value=json.dumps(payload).encode()):
            result = self.client._get("/api/something", as_namespace=True)
        assert isinstance(result, SimpleNamespace)
        assert result.name == "scan1"


# ---------------------------------------------------------------------------
# _post helper
# ---------------------------------------------------------------------------

class TestPost:

    def setup_method(self):
        self.client = _make_client()

    def test_post_returns_true_on_200_no_response_expected(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("requests.post", return_value=mock_resp), \
                patch.object(self.client, "_encrypt", return_value="b64data"):
            result = self.client._post("/api/something", {"x": 1})
        assert result is True

    def test_post_returns_none_on_404(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch("requests.post", return_value=mock_resp), \
                patch.object(self.client, "_encrypt", return_value="b64data"):
            result = self.client._post("/api/something", {"x": 1})
        assert result is None

    def test_post_raises_on_non_200(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        with patch("requests.post", return_value=mock_resp), \
                patch.object(self.client, "_encrypt", return_value="b64data"):
            with pytest.raises(RuntimeError):
                self.client._post("/api/something", {"x": 1})

    def test_post_returns_decrypted_response_when_expected(self):
        payload = {"result": "ok"}
        mock_resp = _encrypted_response(payload)
        with patch("requests.post", return_value=mock_resp), \
                patch.object(self.client, "_encrypt", return_value="b64data"), \
                patch.object(self.client, "_decrypt", return_value=json.dumps(payload).encode()):
            result = self.client._post(
                "/api/something", {"x": 1}, expect_response=True)
        assert result == payload


# ---------------------------------------------------------------------------
# Endpoint methods
# ---------------------------------------------------------------------------

class TestEndpoints:

    def setup_method(self):
        self.client = _make_client()

    # -- Scheduled scans --

    def test_get_scheduled_scans_returns_list(self):
        ns = SimpleNamespace(id="abc", target_id="t1",
                             scan_id="s1", collection_tools=[])
        with patch.object(self.client, "_get", return_value=[ns]):
            result = self.client.get_scheduled_scans()
        assert len(result) == 1
        assert isinstance(result[0], ScheduledScanResponse)
        assert result[0].id == "abc"
        assert result[0].target_id == "t1"
        assert result[0].scan_id == "s1"

    def test_get_scheduled_scans_returns_empty_list_on_none(self):
        with patch.object(self.client, "_get", return_value=None):
            result = self.client.get_scheduled_scans()
        assert result == []

    def test_get_scheduled_scan(self):
        scan = {"scan_id": "xyz", "scope": {}}
        with patch.object(self.client, "_get", return_value=scan):
            result = self.client.get_scheduled_scan("abc123")
        assert result == scan

    # -- Scan status --

    def test_get_scan_status_returns_namespace(self):
        ns = SimpleNamespace(scan_status=1, cancelled_tool_ids=[])
        with patch.object(self.client, "_get", return_value=ns):
            result = self.client.get_scan_status("scan1")
        assert result.scan_status == 1

    def test_update_scan_status_returns_true(self):
        with patch.object(self.client, "_post", return_value=True):
            result = self.client.update_scan_status("sched1", 2)
        assert result is True

    def test_update_scan_status_raises_on_none(self):
        with patch.object(self.client, "_post", return_value=None):
            with pytest.raises(ScanNotFoundException):
                self.client.update_scan_status("sched1", 2)

    # -- Tool status --

    def test_update_tool_status_returns_true(self):
        with patch.object(self.client, "_post", return_value=True):
            result = self.client.update_tool_status("tool1", 1)
        assert result is True

    def test_get_tool_status_returns_value(self):
        ns = SimpleNamespace(status=3)
        with patch.object(self.client, "_get", return_value=ns):
            result = self.client.get_tool_status("tool1")
        assert result == 3

    def test_get_tool_status_returns_none_when_missing(self):
        with patch.object(self.client, "_get", return_value=None):
            result = self.client.get_tool_status("tool1")
        assert result is None

    # -- Collector --

    def test_collector_poll_returns_settings(self):
        settings = {"poll_interval": 60}
        with patch.object(self.client, "_post", return_value=settings):
            result = self.client.collector_poll("some log")
        assert result["poll_interval"] == 60

    def test_update_collector_returns_data(self):
        response = {"tool_name_id_map": {"nmap": "123"}}
        with patch.object(self.client, "_post", return_value=response):
            result = self.client.update_collector({"tools": []})
        assert "tool_name_id_map" in result

    def test_update_collector_raises_on_none(self):
        with patch.object(self.client, "_post", return_value=None):
            with pytest.raises(RuntimeError):
                self.client.update_collector({"tools": []})

    # -- Data import --

    def test_import_data_returns_list(self):
        record_map = [{"old_id": "a", "new_id": "b"}]
        with patch.object(self.client, "_post", return_value=record_map):
            result = self.client.import_data(
                "scan1", "tool1", [{"type": "host"}])
        assert result == record_map

    def test_import_data_returns_empty_list_on_none(self):
        with patch.object(self.client, "_post", return_value=None):
            result = self.client.import_data("scan1", "tool1", [])
        assert result == []

    def test_import_data_sends_correct_payload(self):
        with patch.object(self.client, "_post", return_value=[]) as mock_post:
            self.client.import_data("scan_abc", "tool_xyz", [{"type": "host"}])
        call_args = mock_post.call_args
        payload = call_args[0][1]
        assert payload["scan_id"] == "scan_abc"
        assert payload["tool_id"] == "tool_xyz"
        assert payload["obj_list"] == [{"type": "host"}]

    # -- Subnets / URLs / Hosts --

    def test_get_subnets_formats_correctly(self):
        ns_list = [SimpleNamespace(subnet="10.0.0.0", mask=24)]
        with patch.object(self.client, "_get", return_value=ns_list):
            result = self.client.get_subnets("scan1")
        assert result == ["10.0.0.0/24"]

    def test_get_subnets_returns_empty_on_none(self):
        with patch.object(self.client, "_get", return_value=None):
            result = self.client.get_subnets("scan1")
        assert result == []

    def test_get_hosts_returns_list(self):
        ns_list = [SimpleNamespace(ipv4_addr="1.2.3.4")]
        with patch.object(self.client, "_get", return_value=ns_list):
            result = self.client.get_hosts("scan1")
        assert result == ns_list

    def test_get_hosts_returns_empty_on_none(self):
        with patch.object(self.client, "_get", return_value=None):
            result = self.client.get_hosts("scan1")
        assert result == []

    # -- Wordlist --

    def test_get_wordlist_returns_data(self):
        wl = {"words": ["admin", "password"]}
        with patch.object(self.client, "_get", return_value=wl):
            result = self.client.get_wordlist("wl1")
        assert result == wl

    # -- Port imports --

    def test_import_ports_returns_true(self):
        with patch.object(self.client, "_post", return_value=True):
            result = self.client.import_ports([{"port": 80}])
        assert result is True

    def test_import_ports_ext_returns_true(self):
        with patch.object(self.client, "_post", return_value=True):
            result = self.client.import_ports_ext(
                {"scan_id": "x", "ports": []})
        assert result is True

    # -- Screenshot --

    def test_import_screenshot_returns_true(self):
        with patch.object(self.client, "_post", return_value=True):
            result = self.client.import_screenshot(
                {"url": "https://example.com", "image": "b64data"})
        assert result is True

    def test_import_screenshot_sends_list(self):
        with patch.object(self.client, "_post") as mock_post:
            self.client.import_screenshot({"url": "https://example.com"})
        call_args = mock_post.call_args
        assert call_args[0][0] == "/api/screenshots"
        assert isinstance(call_args[0][1], list)
        assert call_args[0][1][0]["url"] == "https://example.com"

    # -- Shodan --

    def test_import_shodan_data_returns_true(self):
        with patch.object(self.client, "_post", return_value=True):
            result = self.client.import_shodan_data(
                "scan1", [{"ip": "1.2.3.4"}])
        assert result is True


# ---------------------------------------------------------------------------
# Decrypt / session refresh
# ---------------------------------------------------------------------------

class TestDecrypt:

    def setup_method(self):
        self.client = _make_client()

    def test_decrypt_returns_none_when_no_data_key(self):
        result = self.client._decrypt({})
        assert result is None

    def test_decrypt_returns_decrypted_bytes(self):
        expected = b'{"key": "val"}'
        with patch("reverge_collector.tool_utils.decrypt_data", return_value=expected):
            result = self.client._decrypt({"data": "b64stuff"})
        assert result == expected

    def test_decrypt_refreshes_key_on_failure(self):
        refreshed_key = b"refreshed" * 4
        expected = b'{"key": "val"}'

        def fake_decrypt(key, b64):
            if key != refreshed_key:
                raise Exception("bad key")
            return expected

        def fake_refresh():
            self.client.session_key = refreshed_key
            return refreshed_key

        with patch("reverge_collector.tool_utils.decrypt_data", side_effect=fake_decrypt), \
                patch.object(self.client, "_refresh_session_key", side_effect=fake_refresh) as mock_refresh:
            result = self.client._decrypt({"data": "b64stuff"})

        assert result == expected
        mock_refresh.assert_called_once()

    def test_decrypt_returns_none_when_all_attempts_fail(self):
        with patch("reverge_collector.tool_utils.decrypt_data", side_effect=Exception("bad")), \
                patch.object(self.client, "_refresh_session_key"):
            result = self.client._decrypt({"data": "b64stuff"})
        assert result is None
