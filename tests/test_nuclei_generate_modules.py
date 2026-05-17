"""Tests for Nuclei._generate_nuclei_modules (template index parser).

Walks the template-index → YAML-file → CollectionModule build pipeline
without invoking the nuclei binary or touching the real template tree.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch


def _stub_nuclei_tv(template_root_path: str):
    """Build a fake process_wrapper response for `nuclei -duc -tv`."""
    return {
        'exit_code': 0,
        'stdout': '',
        'stderr': f'[INF] Public nuclei-templates version: v10.3.6 ({template_root_path})',
    }


def test_generate_modules_returns_empty_when_nuclei_fails():
    from reverge_collector.nuclei_scan import Nuclei

    with patch(
        'reverge_collector.nuclei_scan.process_wrapper',
        return_value={'exit_code': 2, 'stdout': '', 'stderr': 'boom'},
    ):
        assert Nuclei._generate_nuclei_modules() == []


def test_generate_modules_returns_empty_when_no_template_path():
    from reverge_collector.nuclei_scan import Nuclei

    with patch(
        'reverge_collector.nuclei_scan.process_wrapper',
        return_value={'exit_code': 0, 'stdout': '', 'stderr': 'no version line here'},
    ):
        assert Nuclei._generate_nuclei_modules() == []


def test_generate_modules_returns_empty_when_index_missing(tmp_path):
    from reverge_collector.nuclei_scan import Nuclei

    # Template root exists but no .templates-index file under it
    with patch(
        'reverge_collector.nuclei_scan.process_wrapper',
        return_value=_stub_nuclei_tv(str(tmp_path)),
    ):
        assert Nuclei._generate_nuclei_modules() == []


def test_generate_modules_builds_collection_modules(tmp_path):
    from reverge_collector.nuclei_scan import Nuclei

    root = tmp_path / 'templates'
    root.mkdir()
    # Create two templates with id + info + classification.cpe
    t1 = root / 'cves' / 'cve-1.yaml'
    t1.parent.mkdir(parents=True)
    t1.write_text(
        'id: CVE-2024-0001\n'
        'info:\n'
        '  name: Test Vuln\n'
        '  description: Tests for the vuln\n'
        '  classification:\n'
        '    cpe: "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"\n'
        'variables:\n'
        '  foo: bar\n'
    )
    t2 = root / 'misc' / 'fp.yaml'
    t2.parent.mkdir(parents=True)
    t2.write_text(
        'id: misc-fp\n'
        'info:\n'
        '  name: Misc Test\n'
        '  metadata:\n'
        '    vendor: Vendor\n'
        '    product: Product\n'
    )
    # Index file: template_id,full_path
    index = root / '.templates-index'
    index.write_text(f'CVE-2024-0001,{t1}\nmisc-fp,{t2}\n')

    with patch(
        'reverge_collector.nuclei_scan.process_wrapper',
        return_value=_stub_nuclei_tv(str(root)),
    ):
        modules = Nuclei._generate_nuclei_modules()

    names = [m.name for m in modules]
    assert 'CVE-2024-0001' in names
    assert 'misc-fp' in names
    # cpe wired correctly
    cve_mod = next(m for m in modules if m.name == 'CVE-2024-0001')
    assert cve_mod.cpe == 'cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*'
    misc_mod = next(m for m in modules if m.name == 'misc-fp')
    # Built from vendor+product when classification.cpe is absent
    assert misc_mod.cpe == 'cpe:2.3:a:Vendor:Product:*:*:*:*:*:*:*:*'
    # args carry relative -t <path>
    assert '-t' in cve_mod.args


def test_generate_modules_skips_invalid_index_entries(tmp_path):
    from reverge_collector.nuclei_scan import Nuclei

    root = tmp_path / 'templates'
    root.mkdir()
    t = root / 'ok.yaml'
    t.write_text('id: ok\ninfo:\n  name: ok\n')
    index = root / '.templates-index'
    index.write_text(f'bad-line-without-comma\nok,{t}\n')
    with patch(
        'reverge_collector.nuclei_scan.process_wrapper',
        return_value=_stub_nuclei_tv(str(root)),
    ):
        modules = Nuclei._generate_nuclei_modules()
    names = [m.name for m in modules]
    assert names == ['ok']


def test_generate_modules_skips_template_with_no_id(tmp_path):
    from reverge_collector.nuclei_scan import Nuclei

    root = tmp_path / 'templates'
    root.mkdir()
    no_id = root / 'noid.yaml'
    no_id.write_text('info:\n  name: nothing\n')
    index = root / '.templates-index'
    index.write_text(f'noid,{no_id}\n')
    with patch(
        'reverge_collector.nuclei_scan.process_wrapper',
        return_value=_stub_nuclei_tv(str(root)),
    ):
        modules = Nuclei._generate_nuclei_modules()
    assert modules == []


def test_generate_modules_skips_unreadable_yaml(tmp_path):
    from reverge_collector.nuclei_scan import Nuclei

    root = tmp_path / 'templates'
    root.mkdir()
    broken = root / 'broken.yaml'
    broken.write_text(': : : invalid : yaml : ::')
    index = root / '.templates-index'
    index.write_text(f'broken,{broken}\n')
    with patch(
        'reverge_collector.nuclei_scan.process_wrapper',
        return_value=_stub_nuclei_tv(str(root)),
    ):
        modules = Nuclei._generate_nuclei_modules()
    assert modules == []
