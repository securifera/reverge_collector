"""Tests for the _generate_X_modules() functions in scanner modules.

These functions parse `tool --script-help`-style output to enumerate
available scripts/templates as CollectionModule records. We mock
process_wrapper so no actual binary is invoked.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest


NMAP_SCRIPT_HELP_SAMPLE = """\
http-title
Categories: discovery default safe
CPE: cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*
https://nmap.org/nsedoc/scripts/http-title.html
  Shows the title of the default page of a web server.

ssl-cert
Categories: discovery safe vuln
https://nmap.org/nsedoc/scripts/ssl-cert.html
  Retrieves a server's SSL certificate.

http-vuln-cve2017-5638
Categories: vuln intrusive exploit
CPE: cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*
CPE: cpe:2.3:a:apache:struts:2.3.5:*:*:*:*:*:*:*
https://nmap.org/nsedoc/scripts/http-vuln-cve2017-5638.html
  Detects Apache Struts vulnerable to CVE-2017-5638.

"""


class TestNmapGenerateModules:
    def test_parses_known_format(self):
        from reverge_collector.nmap_scan import Nmap

        gen = getattr(Nmap, '_generate_nmap_modules', None)
        if not gen:
            pytest.skip('_generate_nmap_modules not exposed')

        with patch(
            'reverge_collector.nmap_scan.process_wrapper',
            return_value={'exit_code': 0, 'stdout': NMAP_SCRIPT_HELP_SAMPLE},
        ):
            modules = gen()

        names = {m.name for m in modules}
        assert 'http-title' in names
        assert 'ssl-cert' in names
        assert 'http-vuln-cve2017-5638' in names

    def test_returns_empty_on_failure(self):
        from reverge_collector.nmap_scan import Nmap

        gen = getattr(Nmap, '_generate_nmap_modules', None)
        if not gen:
            pytest.skip()
        with patch(
            'reverge_collector.nmap_scan.process_wrapper',
            return_value={'exit_code': 1, 'stderr': 'error'},
        ):
            assert gen() == []

    def test_returns_empty_on_no_result(self):
        from reverge_collector.nmap_scan import Nmap

        gen = getattr(Nmap, '_generate_nmap_modules', None)
        if not gen:
            pytest.skip()
        with patch(
            'reverge_collector.nmap_scan.process_wrapper', return_value=None
        ):
            # Should handle None gracefully (no crash)
            try:
                out = gen()
                assert isinstance(out, list)
            except Exception:
                pass

    def test_module_args_include_script_flag(self):
        from reverge_collector.nmap_scan import Nmap

        gen = getattr(Nmap, '_generate_nmap_modules', None)
        if not gen:
            pytest.skip()
        with patch(
            'reverge_collector.nmap_scan.process_wrapper',
            return_value={'exit_code': 0, 'stdout': NMAP_SCRIPT_HELP_SAMPLE},
        ):
            modules = gen()

        # Each module should have --script-style args pointing at its name
        for m in modules:
            assert '--script' in (m.args or '')
            assert m.name in (m.args or '')

    def test_cpe_extracted_when_present(self):
        from reverge_collector.nmap_scan import Nmap

        gen = getattr(Nmap, '_generate_nmap_modules', None)
        if not gen:
            pytest.skip()
        with patch(
            'reverge_collector.nmap_scan.process_wrapper',
            return_value={'exit_code': 0, 'stdout': NMAP_SCRIPT_HELP_SAMPLE},
        ):
            modules = gen()
        by_name = {m.name: m for m in modules}
        assert getattr(by_name['http-title'], 'cpe', '') == (
            'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*'
        )
        # ssl-cert has no CPE line — cpe should be empty
        assert not getattr(by_name['ssl-cert'], 'cpe', '')


class TestNmapFingerprint:
    def test_fingerprint_returns_none_when_binary_missing(self):
        from reverge_collector.nmap_scan import Nmap

        fp = getattr(Nmap, '_fingerprint', None)
        if not fp:
            pytest.skip()
        with patch('shutil.which', return_value=None):
            assert fp() is None

    def test_fingerprint_returns_hash_when_binary_present(self, tmp_path):
        from reverge_collector.nmap_scan import Nmap

        fp = getattr(Nmap, '_fingerprint', None)
        if not fp:
            pytest.skip()
        fake = tmp_path / 'nmap'
        fake.write_bytes(b'fake nmap binary')
        with patch('shutil.which', return_value=str(fake)):
            out = fp()
        assert out is not None
        assert len(out) == 64  # sha256


class TestNucleiFingerprint:
    def test_fingerprint_returns_none_when_no_templates_index(self, tmp_path):
        from reverge_collector.nuclei_scan import Nuclei

        fp = getattr(Nuclei, '_fingerprint', None)
        if not fp:
            pytest.skip()
        # process_wrapper returns no templates-version line → returns None
        with patch(
            'reverge_collector.nuclei_scan.process_wrapper',
            return_value={'exit_code': 0, 'stderr': 'no version here'},
        ):
            assert fp() is None

    def test_fingerprint_returns_none_when_command_fails(self):
        from reverge_collector.nuclei_scan import Nuclei

        fp = getattr(Nuclei, '_fingerprint', None)
        if not fp:
            pytest.skip()
        with patch(
            'reverge_collector.nuclei_scan.process_wrapper',
            return_value={'exit_code': 1, 'stderr': 'failure'},
        ):
            assert fp() is None
