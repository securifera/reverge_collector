#!/usr/bin/env python3
"""
Enrich nuclei technology-detection templates with CPE data.

Phase 1: Add info.classification.cpe from metadata.vendor + metadata.product
Phase 2: Add info.classification.cpe from metadata.plugin_namespace (WP plugins)
Phase 3: Inject per-matcher `cpe:` field on named matchers in single-CPE templates

Usage:
    python3 enrich_template_cpes.py [--dry-run] [--templates-dir DIR]
"""

import argparse
import re
import sys
from pathlib import Path
from typing import Optional


def make_cpe(vendor: str, product: str, target_sw: str = "*") -> str:
    v = vendor.strip().lower().replace(" ", "_")
    p = product.strip().lower().replace(" ", "_")
    return f"cpe:2.3:a:{v}:{p}:*:*:*:*:*:{target_sw}:*:*"


def has_classification_cpe(text: str) -> bool:
    # classification: is at 2-space indent inside info:
    # its child cpe: is at 4-space indent
    return bool(
        re.search(r"^  classification:", text, re.MULTILINE) and
        re.search(r"^    cpe: cpe:", text, re.MULTILINE)
    )


def get_classification_cpe(text: str) -> Optional[str]:
    m = re.search(
        r"^  classification:\s*\n(?:.*\n)*?    cpe:\s*(cpe:[^\s#]+)",
        text, re.MULTILINE
    )
    return m.group(1).strip() if m else None


def get_metadata_field(text: str, field: str) -> Optional[str]:
    """Extract a 4-space-indented scalar value from any metadata field."""
    m = re.search(rf"^    {re.escape(field)}:\s*(.+)$", text, re.MULTILINE)
    return m.group(1).strip() if m else None


def inject_classification_block(text: str, cpe: str) -> Optional[str]:
    block = f"  classification:\n    cpe: {cpe}\n"
    # Preferred: before `  metadata:`
    m = re.search(r"^  metadata:", text, re.MULTILINE)
    if m:
        return text[:m.start()] + block + text[m.start():]
    # Fallback: after `  severity:` line
    m = re.search(r"^  severity:.*\n", text, re.MULTILINE)
    if m:
        return text[:m.end()] + block + text[m.end():]
    # Fallback: after description block (may use | multiline)
    m = re.search(r"^  description:.*\n(?:    .*\n)*", text, re.MULTILINE)
    if m:
        return text[:m.end()] + block + text[m.end():]
    return None


def inject_matcher_cpes(text: str, cpe: str) -> tuple:
    """
    Inject `        cpe: <cpe>` after each 8-space `name:` line that is
    inside a `matchers:` block (not inside `extractors:`).
    Returns (new_text, injection_count).
    """
    lines = text.splitlines(keepends=True)
    result = []
    injected = 0
    in_matchers = False
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip('\n')

        # Track matchers: vs extractors: sections (4-space indent inside http item)
        if re.match(r'^    matchers:', stripped):
            in_matchers = True
        elif re.match(r'^    extractors:', stripped):
            in_matchers = False
        elif re.match(r'^[a-z]', stripped) and stripped:
            # Top-level key — exit any block
            in_matchers = False

        if in_matchers and re.match(r'^        name:\s+\S', stripped):
            result.append(line)
            # Peek ahead; skip if already `        cpe:`
            j = i + 1
            while j < len(lines) and lines[j].strip() == "":
                j += 1
            if j < len(lines) and re.match(r'^        cpe:', lines[j]):
                pass  # already set
            else:
                result.append(f"        cpe: {cpe}\n")
                injected += 1
            i += 1
            continue

        result.append(line)
        i += 1
    return "".join(result), injected


def strip_digest(text: str) -> str:
    return re.sub(r"\n# digest: [0-9a-f:]+\s*$", "\n", text)


def process_file(path: Path, dry_run: bool, stats: dict, report: list) -> None:
    text = path.read_text(encoding="utf-8")
    changed = False

    # Phase 1 & 2: add classification.cpe if missing
    if not has_classification_cpe(text):
        cpe = None
        source = None

        vendor = get_metadata_field(text, "vendor")
        product = get_metadata_field(text, "product")
        if vendor and product:
            v = vendor.strip("\"'\\").lower()
            p = product.strip("\"'\\").lower()
            if v and p and v != "n/a" and p != "n/a":
                cpe = make_cpe(v, p)
                source = "vendor_product"

        if cpe is None:
            ns = get_metadata_field(text, "plugin_namespace")
            if ns:
                ns = ns.strip("\"'")
                cpe = make_cpe(ns, ns, target_sw="wordpress")
                source = "plugin_namespace"

        if cpe:
            new_text = inject_classification_block(text, cpe)
            if new_text is None:
                report.append(
                    {"file": str(path), "issue": f"No injection point (source={source})", "cpe": cpe})
            else:
                text = new_text
                changed = True
                stats[f"added_cpe_{source}"] = stats.get(
                    f"added_cpe_{source}", 0) + 1
        else:
            report.append({"file": str(
                path), "issue": "No vendor/product or plugin_namespace — manual CPE needed", "cpe": ""})
            stats["needs_manual"] = stats.get("needs_manual", 0) + 1

    # Phase 3: inject per-matcher cpe: on named matchers
    cpe = get_classification_cpe(text)
    if cpe:
        new_text, count = inject_matcher_cpes(text, cpe)
        if count > 0:
            text = new_text
            changed = True
            stats["matcher_cpes_injected"] = stats.get(
                "matcher_cpes_injected", 0) + count
            stats["templates_with_matcher_cpe"] = stats.get(
                "templates_with_matcher_cpe", 0) + 1

    if changed:
        text = strip_digest(text)
        if not dry_run:
            path.write_text(text, encoding="utf-8")
        stats["files_changed"] = stats.get("files_changed", 0) + 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--templates-dir",
                        default="/opt/reverge_collector/nuclei-templates/http/technologies")
    parser.add_argument(
        "--report-file", default="/tmp/cpe_enrichment_report.txt")
    args = parser.parse_args()

    tdir = Path(args.templates_dir)
    if not tdir.is_dir():
        print(f"ERROR: {tdir} is not a directory", file=sys.stderr)
        sys.exit(1)

    stats: dict = {}
    report: list = []
    all_yaml = sorted(tdir.rglob("*.yaml"))
    print(f"Processing {len(all_yaml)} templates ...")

    for path in all_yaml:
        try:
            process_file(path, dry_run=args.dry_run,
                         stats=stats, report=report)
        except Exception as e:
            print(f"  ERROR {path}: {e}", file=sys.stderr)
            report.append(
                {"file": str(path), "issue": f"Script error: {e}", "cpe": ""})

    print("\n=== Results ===")
    for k, v in sorted(stats.items()):
        print(f"  {k}: {v}")
    print(f"\n  Templates needing manual CPE: {len(report)}")

    with open(args.report_file, "w") as f:
        f.write("Templates requiring manual CPE enrichment\n")
        f.write("=" * 60 + "\n\n")
        for entry in report:
            f.write(f"FILE:  {entry['file']}\n")
            f.write(f"ISSUE: {entry['issue']}\n")
            if entry["cpe"]:
                f.write(f"CPE:   {entry['cpe']}\n")
            f.write("\n")
    print(f"Report: {args.report_file}")
    if args.dry_run:
        print("\n[DRY RUN — no files written]")


if __name__ == "__main__":
    main()
