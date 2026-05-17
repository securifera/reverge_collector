"""Tests for webcap_scan.parse_args and parse_webcap_output."""

from __future__ import annotations

import base64
import json
import os

# ===========================================================================
# parse_args
# ===========================================================================


class TestParseArgs:
    def test_defaults_when_empty_string(self):
        from reverge_collector.webcap_scan import parse_args

        assert parse_args('') == (5, 5, 'jpeg', 100)

    def test_defaults_when_none(self):
        from reverge_collector.webcap_scan import parse_args

        assert parse_args(None) == (5, 5, 'jpeg', 100)

    def test_extracts_all_values(self):
        from reverge_collector.webcap_scan import parse_args

        out = parse_args('--timeout 20 --threads 8 --quality 90 --format png')
        assert out == (20, 8, 'png', 90)

    def test_clamps_quality_to_max_100(self):
        from reverge_collector.webcap_scan import parse_args

        assert parse_args('--quality 200')[3] == 100

    def test_clamps_quality_to_min_1(self):
        from reverge_collector.webcap_scan import parse_args

        assert parse_args('--quality 0')[3] == 1

    def test_invalid_numeric_uses_default(self):
        from reverge_collector.webcap_scan import parse_args

        out = parse_args('--timeout xx --threads yy --quality zz')
        # Each invalid value falls back to the default
        assert out == (5, 5, 'jpeg', 100)

    def test_unsupported_format_keeps_default(self):
        from reverge_collector.webcap_scan import parse_args

        out = parse_args('--format bmp')
        assert out[2] == 'jpeg'

    def test_supported_format_overrides(self):
        from reverge_collector.webcap_scan import parse_args

        for fmt in ('jpeg', 'png', 'webp'):
            assert parse_args(f'--format {fmt}')[2] == fmt


# ===========================================================================
# parse_webcap_output
# ===========================================================================


def _b64(content: bytes) -> str:
    return base64.b64encode(content).decode()


def _write_meta(tmp_path, entries):
    p = tmp_path / 'screenshots.json'
    with open(p, 'w') as f:
        for entry in entries:
            f.write(json.dumps(entry) + '\n')
    return str(p)


class TestParseWebcapOutput:
    def test_returns_empty_when_meta_missing(self, tmp_path):
        from reverge_collector.webcap_scan import parse_webcap_output

        assert parse_webcap_output(str(tmp_path / 'missing'), 'ti') == []

    def test_skips_blank_lines(self, tmp_path):
        from reverge_collector.webcap_scan import parse_webcap_output

        p = tmp_path / 'screenshots.json'
        with open(p, 'w') as f:
            f.write('\n\n')
            f.write(
                json.dumps(
                    {
                        'path': '/',
                        'port_id': 'p1',
                        'status_code': 200,
                        'image_data': _b64(b'X'),
                        'title': 't',
                        'http_endpoint_data_id': None,
                    }
                )
                + '\n'
            )
        records = parse_webcap_output(str(p), 'ti')
        assert any(type(r).__name__ == 'Screenshot' for r in records)

    def test_builds_full_record_chain(self, tmp_path):
        from reverge_collector.webcap_scan import parse_webcap_output

        meta = _write_meta(
            tmp_path,
            [
                {
                    'path': '/admin',
                    'port_id': 'port-1',
                    'status_code': 200,
                    'image_data': _b64(b'IMG'),
                    'title': 'Welcome',
                    'http_endpoint_data_id': None,
                    'domain': 'example.com',
                }
            ],
        )
        records = parse_webcap_output(meta, 'ti')
        types = [type(r).__name__ for r in records]
        assert 'Screenshot' in types
        assert 'Domain' in types
        assert 'ListItem' in types
        assert 'HttpEndpoint' in types
        assert 'HttpEndpointData' in types

    def test_dedups_screenshots(self, tmp_path):
        from reverge_collector.webcap_scan import parse_webcap_output

        same = _b64(b'SAMEBYTES')
        meta = _write_meta(
            tmp_path,
            [
                {
                    'path': '/a',
                    'port_id': 'p1',
                    'status_code': 200,
                    'image_data': same,
                    'title': 't',
                    'http_endpoint_data_id': None,
                },
                {
                    'path': '/b',
                    'port_id': 'p1',
                    'status_code': 200,
                    'image_data': same,
                    'title': 't',
                    'http_endpoint_data_id': None,
                },
            ],
        )
        records = parse_webcap_output(meta, 'ti')
        unique = {id(r) for r in records if type(r).__name__ == 'Screenshot'}
        assert len(unique) == 1

    def test_preserves_endpoint_data_id_when_provided(self, tmp_path):
        from reverge_collector.webcap_scan import parse_webcap_output

        meta = _write_meta(
            tmp_path,
            [
                {
                    'path': '/',
                    'port_id': 'p1',
                    'status_code': 200,
                    'image_data': _b64(b'X'),
                    'title': 'y',
                    'http_endpoint_data_id': 'epd-keep',
                }
            ],
        )
        records = parse_webcap_output(meta, 'ti')
        epds = [r for r in records if type(r).__name__ == 'HttpEndpointData']
        assert epds and epds[0].id == 'epd-keep'
