"""Utilities for archiving and cleaning completed scan directories.

This module intentionally avoids Luigi so cleanup can run in minimal
collector environments without workflow-engine dependencies.
"""

import logging
import os
import shutil
import traceback
from datetime import datetime


def scan_cleanup_func(scan_id: str) -> bool:
    """Archive ``<cwd>/<scan_id>`` to ``<cwd>/archive`` and remove source dir.

    Returns ``True`` when cleanup succeeds or there is nothing to clean,
    and ``False`` on archive/remove failures.
    """
    if not scan_id:
        return True

    cwd = os.getcwd()
    dir_path = os.path.join(cwd, scan_id)

    # Nothing to clean is treated as success.
    if not os.path.isdir(dir_path):
        return True

    try:
        archive_dir = os.path.join(cwd, "archive")
        if not os.path.isdir(archive_dir):
            os.makedirs(archive_dir)
            os.chmod(archive_dir, 0o777)

        date_str = datetime.now().strftime("%Y%m%d%H%M%S")
        archive_prefix = os.path.join(archive_dir, f"{scan_id}_{date_str}")
        shutil.make_archive(archive_prefix, "zip", dir_path)
        shutil.rmtree(dir_path)
        return True
    except Exception as exc:
        logging.getLogger(__name__).error(
            "[-] Error during scan cleanup process: %s", str(exc)
        )
        logging.getLogger(__name__).error(
            "[-] Traceback: %s", traceback.format_exc()
        )
        return False
