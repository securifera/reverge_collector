"""Tests for the small enum.__str__ methods and tiny helper paths in
data_model that haven't been covered yet."""

from __future__ import annotations

import pytest

from reverge_collector import data_model
from reverge_collector.data_model import (
    CollectionToolStatus,
    CollectorType,
    Record,
    RecordTag,
    ScanStatus,
    ServerRecordType,
    update_scope_array,
)


# ===========================================================================
# enum.__str__
# ===========================================================================


class TestScanStatusStr:
    @pytest.mark.parametrize('value,expected', [
        (ScanStatus.CREATED, 'CREATED'),
        (ScanStatus.RUNNING, 'RUNNING'),
        (ScanStatus.COMPLETED, 'COMPLETED'),
        (ScanStatus.CANCELLED, 'CANCELLED'),
        (ScanStatus.ERROR, 'ERROR'),
    ])
    def test_str(self, value, expected):
        assert str(value) == expected


class TestCollectionToolStatusStr:
    @pytest.mark.parametrize('value,expected', [
        (CollectionToolStatus.CREATED, 'CREATED'),
        (CollectionToolStatus.RUNNING, 'RUNNING'),
        (CollectionToolStatus.COMPLETED, 'COMPLETED'),
        (CollectionToolStatus.ERROR, 'ERROR'),
        (CollectionToolStatus.CANCELLED, 'CANCELLED'),
        (CollectionToolStatus.IMPORT_FAILED, 'IMPORT_FAILED'),
    ])
    def test_str(self, value, expected):
        assert str(value) == expected


class TestCollectorTypeStr:
    @pytest.mark.parametrize('value,expected', [
        (CollectorType.PASSIVE, 'PASSIVE'),
        (CollectorType.ACTIVE, 'ACTIVE'),
    ])
    def test_str(self, value, expected):
        assert str(value) == expected


class TestRecordTagStr:
    @pytest.mark.parametrize('value,expected', [
        (RecordTag.LOCAL, 'LOCAL'),
        (RecordTag.REMOTE, 'REMOTE'),
        (RecordTag.SCOPE, 'SCOPE'),
    ])
    def test_str(self, value, expected):
        assert str(value) == expected


class TestServerRecordTypeStr:
    @pytest.mark.parametrize('value,expected', [
        (ServerRecordType.HOST, 'Host'),
        (ServerRecordType.PORT, 'Port'),
        (ServerRecordType.DOMAIN, 'Domain'),
        (ServerRecordType.HTTP_ENDPOINT, 'HttpEndpoint'),
        (ServerRecordType.VULNERABILITY, 'Vuln'),
        (ServerRecordType.CERTIFICATE, 'Certificate'),
        (ServerRecordType.CPE, 'Cpe'),
        (ServerRecordType.SUBNET, 'Subnet'),
    ])
    def test_str(self, value, expected):
        assert str(value) == expected


# ===========================================================================
# update_scope_array
# ===========================================================================


class TestUpdateScopeArray:
    def test_no_updates_emits_jsonable_for_each_record(self):
        h = data_model.Host()
        h.ipv4_addr = '10.0.0.1'
        out = update_scope_array({h.id: h}, updated_record_map=None)
        assert isinstance(out, list)
        assert len(out) == 1
        assert out[0]['id'] == h.id
        assert out[0]['type'] == 'host'

    def test_updates_remap_ids_on_records(self):
        h = data_model.Host()
        h.ipv4_addr = '10.0.0.1'
        original_id = h.id
        updates = [{'orig_id': original_id, 'db_id': 'server-assigned-id'}]
        out = update_scope_array({original_id: h}, updated_record_map=updates)
        # The Host record now carries the server's id
        assert h.id == 'server-assigned-id'
        assert out[0]['id'] == 'server-assigned-id'

    def test_empty_record_map_returns_empty(self):
        out = update_scope_array({}, updated_record_map=None)
        assert out == []
