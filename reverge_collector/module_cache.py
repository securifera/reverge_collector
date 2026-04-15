"""
Module discovery result cache for security tool integration.

Tools that expose a ``modules_func()`` must enumerate their available
scripts/templates/modules on every startup, which can be slow (nmap has 600+
NSE scripts, nuclei has thousands of templates, metasploit has thousands of
modules).  This module provides a simple on-disk cache keyed by a *fingerprint*
of the tool's installed state so that the expensive enumeration is only repeated
when the tool has actually changed.

Cache files live at:
    ``/opt/collector/module_cache/<tool_name>_modules.json``

Cache file format::

    {
        "fingerprint": "<tool-state-hash-or-version-string>",
        "modules": [
            {"name": "...", "description": "...", "args": "..."},
            ...
        ]
    }

Fingerprint strategies per tool are implemented as ``_fingerprint()`` static
methods on each tool's class (e.g. ``Nuclei._fingerprint``,
``Nmap._fingerprint``) so that the logic lives alongside the tool it describes.

Usage::

    from reverge_collector.module_cache import get_cached_modules

    def nmap_modules():
        def _generate():
            ...  # expensive enumeration
            return modules
        return get_cached_modules('nmap', Nmap._fingerprint, _generate)

"""

import hashlib
import json
import logging
import os
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Directory where per-tool cache files are stored
CACHE_DIR: str = "/opt/collector/module_cache"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _cache_path(tool_name: str) -> str:
    return os.path.join(CACHE_DIR, f"{tool_name}_modules.json")


def _read_cache(tool_name: str) -> Optional[Dict[str, Any]]:
    """Load a cache file; returns None on any error."""
    path = _cache_path(tool_name)
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r') as fh:
            return json.load(fh)
    except Exception as exc:
        logger.warning(
            "Failed to read module cache for %s: %s", tool_name, exc)
        return None


def _write_cache(tool_name: str, fingerprint: str,
                 modules: List[Any]) -> None:
    """Persist a list of CollectionModule objects to the cache file."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    payload: Dict[str, Any] = {
        "fingerprint": fingerprint,
        "modules": [
            {"name": m.name, "description": m.description, "args": m.args}
            for m in modules
        ],
    }
    path = _cache_path(tool_name)
    try:
        with open(path, 'w') as fh:
            json.dump(payload, fh, indent=2)
        logger.debug("Wrote module cache for %s (%d entries, fingerprint=%s)",
                     tool_name, len(modules), fingerprint)
    except Exception as exc:
        logger.warning(
            "Failed to write module cache for %s: %s", tool_name, exc)


def _modules_from_cache(raw: Dict[str, Any]) -> List[Any]:
    """Reconstruct CollectionModule objects from a cache dict."""
    # Import lazily to avoid circular imports
    from reverge_collector import data_model
    modules = []
    for entry in raw.get("modules", []):
        m = data_model.CollectionModule()
        m.name = entry.get("name")
        m.description = entry.get("description")
        m.args = entry.get("args")
        modules.append(m)
    return modules


def sha256_file(path: str) -> str:
    """Return the hex SHA-256 digest of a file."""
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def get_cached_modules(
    tool_name: str,
    fingerprint_func: Callable[[], Optional[str]],
    generate_func: Callable[[], List[Any]],
) -> List[Any]:
    """Return cached modules when fingerprint matches, otherwise regenerate.

    Args:
        tool_name:        Identifier used for the cache file (e.g. ``'nmap'``).
        fingerprint_func: Zero-argument callable returning a string that uniquely
                          identifies the current installed state of the tool.
                          Returns ``None`` when the state cannot be determined
                          (tool not installed / server unreachable).
        generate_func:    Zero-argument callable that performs the expensive
                          module discovery and returns a list of
                          ``CollectionModule`` objects.

    Returns:
        List of ``CollectionModule`` objects, sourced from cache when valid.

    Behaviour when ``fingerprint_func`` returns ``None`` (tool unreachable):
        The existing cache is returned as-is so that a temporarily unavailable
        service (e.g. MSF RPC not yet started) does not wipe the module list.
        If there is no cache, ``generate_func`` is called as a last resort.
    """
    fingerprint: Optional[str] = None
    try:
        fingerprint = fingerprint_func()
    except Exception as exc:
        logger.debug("fingerprint_func for %s raised: %s", tool_name, exc)

    if fingerprint:
        cached = _read_cache(tool_name)
        cached_fp = cached.get("fingerprint") if cached else None
        if cached and cached_fp == fingerprint:
            logger.debug("Module cache hit for %s (fingerprint=%s)",
                         tool_name, fingerprint)
            return _modules_from_cache(cached)

        # Fingerprint changed or no cache → regenerate and persist
        if cached and cached_fp != fingerprint:
            logger.debug(
                "Module cache miss for %s: fingerprint changed "
                "(cached=%s, current=%s), regenerating …",
                tool_name, cached_fp, fingerprint,
            )
        else:
            logger.debug(
                "Module cache miss for %s: no cache file found "
                "(fingerprint=%s), regenerating …",
                tool_name, fingerprint,
            )
        modules = generate_func()
        logger.debug("Regeneration for %s returned %d module(s)",
                     tool_name, len(modules))
        if modules:
            _write_cache(tool_name, fingerprint, modules)
        else:
            logger.debug(
                "Skipping cache write for %s: generate_func returned no modules",
                tool_name,
            )
        return modules

    else:
        # Cannot determine fingerprint — return stale cache if available
        logger.debug("fingerprint_func returned None for %s", tool_name)
        cached = _read_cache(tool_name)
        if cached:
            logger.debug("No fingerprint for %s; returning stale cache (%d entries)",
                         tool_name, len(cached.get("modules", [])))
            return _modules_from_cache(cached)

        # No cache at all — try live generation (may return empty list)
        logger.debug("No fingerprint and no cache for %s, attempting generation …",
                     tool_name)
        return generate_func()
