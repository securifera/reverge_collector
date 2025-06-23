import os
import shutil
import luigi
import traceback
import shutil
import logging

from datetime import datetime


def scan_cleanup_func(scan_id):
    luigi_run_result = luigi.build([ScanCleanup(
        scan_id=scan_id)], local_scheduler=True, detailed_summary=True)
    if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
        return False
    return True


class ExternalDataDirectory(luigi.ExternalTask):
    directory_path = luigi.Parameter()

    def output(self):
        return luigi.LocalTarget(self.directory_path, format=luigi.format.Nop)

    def complete(self):
        # Custom completeness check to ensure the directory exists
        return os.path.exists(self.directory_path) and os.path.isdir(self.directory_path)


class ScanCleanup(luigi.ExternalTask):

    scan_id = luigi.Parameter()

    def requires(self):

        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + self.scan_id
        return ExternalDataDirectory(dir_path)

    def run(self):

        archive_zip_file = None
        if self.scan_id:

            dir_path = self.input().path

            # Delete all the files defined in the cleanup file
            try:
                # Ensure archive dir exists
                cwd = os.getcwd()
                archive_dir = cwd + os.path.sep + "archive"
                if not os.path.isdir(archive_dir):
                    os.makedirs(archive_dir)
                    os.chmod(archive_dir, 0o777)

                # Convert date to str
                now_time = datetime.now()
                date_str = now_time.strftime("%Y%m%d%H%M%S")
                archive_zip_file = archive_dir + os.path.sep + self.scan_id + "_" + date_str

                # Create zip archive
                shutil.make_archive(archive_zip_file, 'zip', dir_path)

                # Remove scan dir
                shutil.rmtree(dir_path)

            except Exception as e:
                logging.getLogger(__name__).error(
                    "[-] Error deleting output directory: %s" % str(e))
                pass

        return luigi.LocalTarget(archive_zip_file)
