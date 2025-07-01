"""
Waluigi Scan Cleanup Module

This module provides functionality for cleaning up scan data and archiving results
after security scanning operations are complete. It handles the archival of scan
output directories and cleanup of temporary files.

The module includes:
- Scan data archiving to ZIP format
- Directory cleanup and removal
- Luigi task orchestration for cleanup operations
- Error handling and logging for cleanup failures

Classes:
    ExternalDataDirectory: Luigi task for validating scan data directories
    ScanCleanup: Main Luigi task for archiving and cleaning scan data

Functions:
    scan_cleanup_func: Entry point function for cleanup operations
"""

import os
import shutil
import luigi
import traceback
import logging
from datetime import datetime
from typing import Optional, Union


def scan_cleanup_func(scan_id: str) -> bool:
    """
    Execute scan cleanup operations for a given scan ID.

    This function orchestrates the cleanup process by building and executing
    a Luigi ScanCleanup task. It handles the archival of scan data and cleanup
    of temporary files and directories.

    Args:
        scan_id (str): Unique identifier for the scan to be cleaned up

    Returns:
        bool: True if cleanup was successful, False if cleanup failed

    Example:
        >>> success = scan_cleanup_func("scan_20240101_001")
        >>> if success:
        ...     print("Scan cleanup completed successfully")
        ... else:
        ...     print("Scan cleanup failed")

    Note:
        Uses Luigi's local scheduler to execute the cleanup task.
        Detailed summary is enabled for comprehensive logging.
    """
    luigi_run_result = luigi.build([ScanCleanup(
        scan_id=scan_id)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True


class ExternalDataDirectory(luigi.ExternalTask):
    """
    Luigi task for validating external scan data directories.

    This task represents an external directory that should exist and contain
    scan data. It's used as a dependency to ensure that scan data directories
    are present before attempting cleanup operations.

    Attributes:
        directory_path (luigi.Parameter): Path to the directory to validate

    Example:
        >>> task = ExternalDataDirectory(directory_path="/tmp/scan_data")
        >>> is_complete = task.complete()
        >>> target = task.output()
    """

    directory_path = luigi.Parameter()

    def output(self) -> luigi.LocalTarget:
        """
        Define the output target for this task.

        Returns:
            luigi.LocalTarget: Target representing the directory with Nop format
                              (no serialization format required)

        Note:
            Uses luigi.format.Nop since directories don't need serialization
        """
        return luigi.LocalTarget(self.directory_path, format=luigi.format.Nop)

    def complete(self) -> bool:
        """
        Check if the external data directory exists and is valid.

        This method implements a custom completeness check to verify that
        the specified directory exists and is actually a directory (not a file).

        Returns:
            bool: True if directory exists and is valid, False otherwise

        Example:
            >>> task = ExternalDataDirectory(directory_path="/existing/dir")
            >>> print(task.complete())  # True if directory exists
        """
        # Custom completeness check to ensure the directory exists
        return os.path.exists(self.directory_path) and os.path.isdir(self.directory_path)


class ScanCleanup(luigi.ExternalTask):
    """
    Luigi task for archiving scan data and cleaning up scan directories.

    This task handles the complete cleanup process for completed scans, including:
    - Creating timestamped ZIP archives of scan data
    - Removing temporary scan directories
    - Error handling and logging for cleanup operations

    The cleanup process preserves scan results in compressed archives while
    freeing up disk space by removing the original scan directories.

    Attributes:
        scan_id (luigi.Parameter): Unique identifier for the scan to be cleaned up

    Example:
        >>> cleanup_task = ScanCleanup(scan_id="scan_20240101_001")
        >>> dependencies = cleanup_task.requires()
        >>> cleanup_task.run()

    Note:
        Inherits from luigi.ExternalTask to represent cleanup as an external operation
    """

    scan_id = luigi.Parameter()

    def requires(self) -> ExternalDataDirectory:
        """
        Define task dependencies - requires scan data directory to exist.

        This method specifies that the scan data directory must exist before
        cleanup can proceed. It constructs the directory path based on the
        current working directory and scan ID.

        Returns:
            ExternalDataDirectory: Task representing the required scan data directory

        Example:
            >>> cleanup = ScanCleanup(scan_id="test_scan")
            >>> dependency = cleanup.requires()
            >>> print(type(dependency).__name__)  # "ExternalDataDirectory"
        """
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + self.scan_id
        return ExternalDataDirectory(dir_path)

    def run(self) -> luigi.LocalTarget:
        """
        Execute the scan cleanup process.

        This method performs the complete cleanup workflow:
        1. Create an archive directory if it doesn't exist
        2. Generate a timestamped filename for the archive
        3. Create a ZIP archive of the scan data
        4. Remove the original scan directory
        5. Handle errors gracefully with logging

        Returns:
            luigi.LocalTarget: Target pointing to the created ZIP archive file

        Raises:
            Exception: Logs exceptions but continues execution to ensure cleanup attempts

        Example:
            >>> cleanup = ScanCleanup(scan_id="scan_123")
            >>> result = cleanup.run()
            >>> print(result.path)  # Path to created ZIP file

        Note:
            Archive files are named: {scan_id}_{timestamp}.zip
            Timestamp format: YYYYMMDDHHMMSS
        """

        archive_zip_file: Optional[str] = None

        if self.scan_id:
            # Get the path to the scan data directory from the dependency
            dir_path = self.input().path

            # Archive and cleanup process with error handling
            try:
                # Step 1: Ensure archive directory exists
                cwd = os.getcwd()
                archive_dir = cwd + os.path.sep + "archive"
                if not os.path.isdir(archive_dir):
                    os.makedirs(archive_dir)
                    # Set full permissions for archive directory
                    os.chmod(archive_dir, 0o777)

                # Step 2: Generate timestamped archive filename
                now_time = datetime.now()
                date_str = now_time.strftime(
                    "%Y%m%d%H%M%S")  # Format: YYYYMMDDHHMMSS
                archive_zip_file = archive_dir + os.path.sep + self.scan_id + "_" + date_str

                # Step 3: Create ZIP archive of scan data
                # This preserves all scan results in compressed format
                shutil.make_archive(archive_zip_file, 'zip', dir_path)

                # Step 4: Remove original scan directory to free disk space
                # Only done after successful archive creation
                shutil.rmtree(dir_path)

            except Exception as e:
                # Log cleanup errors but don't fail the task
                # This ensures partial cleanup doesn't prevent system operation
                logging.getLogger(__name__).error(
                    "[-] Error during scan cleanup process: %s" % str(e))
                logging.getLogger(__name__).error(
                    "[-] Traceback: %s" % traceback.format_exc())
                pass

        return luigi.LocalTarget(archive_zip_file)
