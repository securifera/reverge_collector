import base64
import os
import shutil
import json
import uuid
import tempfile
from waluigi.recon_manager import ReconManager, ScheduledScanThread
from waluigi.data_model import ScheduledScan, ScanData
from types import SimpleNamespace
from unittest.mock import patch
from waluigi.scan_utils import get_port_byte_array
from waluigi.sqlmap_scan import parse_sqlmap_output
from tests.conftest import get_tool_id

# Realistic sqlmap stdout for a vulnerable parameter (boolean-based blind + time-based)
SQLMAP_VULN_OUTPUT = """\
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.8.3#stable}
|_ -| . [']     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[*] starting @ 12:00:00 /2026-03-20/

[12:00:01] [INFO] testing connection to the target URL
[12:00:02] [INFO] testing if the target URL content is stable
[12:00:03] [INFO] target URL content is stable
[12:00:04] [WARNING] heuristic (basic) test shows that GET parameter 'id' might be injectable
[12:00:05] [INFO] testing for SQL injection on GET parameter 'id'
[12:00:06] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[12:00:07] [INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable
[12:00:08] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[12:00:09] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
sqlmap identified the following injection point(s) with a total of 47 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1234=1234

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT * FROM (SELECT(SLEEP(5)))abc)
---
[12:00:10] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[*] ending @ 12:00:10 /2026-03-20/
"""

# Realistic sqlmap stdout for a clean (non-vulnerable) target
SQLMAP_CLEAN_OUTPUT = """\
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.8.3#stable}
|_ -| . ["]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[*] starting @ 12:00:00 /2026-03-20/

[12:00:01] [INFO] testing connection to the target URL
[12:00:02] [WARNING] the web server responded with an HTTP error code (404) which
could interfere with the results of the tests
[12:00:03] [INFO] heuristic (basic) test shows that the target might not be injectable
[12:00:04] [CRITICAL] all tested parameters do not appear to be injectable
[*] ending @ 12:00:04 /2026-03-20/
"""


class TestSqlmapScan:

    TOOL_NAME = 'sqlmap'
    TEST_SCAN_ID = format(uuid.uuid4().int, 'x')
    TEST_SCHEDULED_SCAN_ID = format(uuid.uuid4().int, 'x')

    def _build_scheduled_scan(self, recon_manager, scan_id, scheduled_scan_id, args='--batch --level=1 --risk=1'):
        """Helper that constructs a ScheduledScan object for the test target."""
        tool_id_instance = get_tool_id(recon_manager, self.TOOL_NAME)

        tool_inst = {
            'id': 'b1234567890abcdef1234567890abcde',
            'collection_tool': {
                'wordlists': [],
                'name': self.TOOL_NAME,
                'args': args,
                'tool_type': 2,
                'scan_order': 12,
                'api_key': None,
                'id': tool_id_instance,
            },
            'args_override': None,
            'enabled': 1,
            'status': 0,
            'status_message': None,
            'collection_tool_id': tool_id_instance,
            'scheduled_scan_id': scheduled_scan_id,
            'owner_id': '94cb514e85da4abea6ee227730328619',
        }

        scheduler_inst_object = {
            'id': scheduled_scan_id,
            'scan_id': scan_id,
            'target_id': 1234,
            'collection_tools': [tool_inst],
        }

        data = json.dumps(scheduler_inst_object)
        sched_scan_arr = json.loads(
            data, object_hook=lambda d: SimpleNamespace(**d))

        port_list = '443'
        target_domain = 'www.securifera.com'
        target_ip = '52.4.7.15'
        port_bytes = get_port_byte_array(port_list)
        b64_ports = base64.b64encode(port_bytes).decode()

        scope = {
            'b64_port_bitmap': b64_ports,
            'obj_list': [
                {
                    'type': 'port',
                    'id': 'c14918af17294944bf8db41f0ec1dc63',
                    'parent': {'type': 'host', 'id': 'eb45abca98834ad4a525dac9a6879141'},
                    'data': {'port': 443, 'proto': 0, 'secure': 1},
                    'tags': [3],
                },
                {
                    'type': 'domain',
                    'id': 'aa6775050f374f6f8b05fc2a94c5c629',
                    'parent': {'type': 'host', 'id': 'eb45abca98834ad4a525dac9a6879141'},
                    'data': {'name': target_domain},
                    'tags': [3],
                },
                {
                    'type': 'host',
                    'id': 'eb45abca98834ad4a525dac9a6879141',
                    'data': {'ipv4_addr': target_ip},
                    'tags': [3],
                },
            ],
        }

        scan_data = {'scan_id': scan_id, 'scope': scope}
        return sched_scan_arr, scan_data

    def test_sqlmap_scan_success(self, recon_manager):

        scan_id = self.TEST_SCAN_ID
        scheduled_scan_id = self.TEST_SCHEDULED_SCAN_ID

        sched_scan_arr, scan_data = self._build_scheduled_scan(
            recon_manager, scan_id, scheduled_scan_id
        )

        scan_thread = ScheduledScanThread(recon_manager, None)
        with patch.object(ReconManager, 'get_scheduled_scan', return_value=scan_data):
            with patch.object(ReconManager, 'get_wordlist', return_value=None):

                scheduled_scan_obj = ScheduledScan(scan_thread, sched_scan_arr)

                first_key = next(iter(scheduled_scan_obj.collection_tool_map))
                first_tool = scheduled_scan_obj.collection_tool_map[first_key]

                # Set the current tool
                scheduled_scan_obj.current_tool = first_tool.collection_tool
                if first_tool.args_override:
                    scheduled_scan_obj.current_tool.args = first_tool.args_override

                result = recon_manager.scan_func(scheduled_scan_obj)
                assert result == True

                output_dir = "/tmp/%s" % scheduled_scan_id
                assert os.path.exists(output_dir) == True

                target_output = "%s/%s-outputs/sqlmap_outputs_%s" % (
                    output_dir, self.TOOL_NAME, scheduled_scan_id
                )
                assert os.path.exists(target_output) == True

                # Verify the manifest file has the expected structure
                with open(target_output, 'r') as f:
                    file_contents = f.read()
                    assert len(file_contents) > 0
                    scan_data_dict = json.loads(file_contents)

                    url_to_id_map = scan_data_dict['url_to_id_map']
                    for url_str in url_to_id_map:
                        obj_data = url_to_id_map[url_str]
                        output_file = obj_data['output_file']
                        # The per-URL stdout capture file should exist
                        assert os.path.exists(output_file) == True

    def test_sqlmap_import_success(self, recon_manager):

        scan_id = self.TEST_SCAN_ID
        scheduled_scan_id = self.TEST_SCHEDULED_SCAN_ID

        sched_scan_arr, scan_data = self._build_scheduled_scan(
            recon_manager, scan_id, scheduled_scan_id
        )

        output_dir = "/tmp/%s" % scheduled_scan_id
        try:
            scan_thread = ScheduledScanThread(recon_manager, None)
            with patch.object(ReconManager, 'get_scheduled_scan', return_value=scan_data):
                with patch.object(ReconManager, 'get_wordlist', return_value=None):

                    scheduled_scan_obj = ScheduledScan(
                        scan_thread, sched_scan_arr)
                    first_key = next(
                        iter(scheduled_scan_obj.collection_tool_map))
                    first_tool = scheduled_scan_obj.collection_tool_map[first_key]

                    # Set the current tool
                    scheduled_scan_obj.current_tool = first_tool.collection_tool
                    if first_tool.args_override:
                        scheduled_scan_obj.current_tool.args = first_tool.args_override

                    with patch.object(ReconManager, 'import_data', return_value={}):
                        result = recon_manager.import_func(scheduled_scan_obj)
                        assert result == True

                        # tool_import_json is only written when sqlmap finds
                        # injection points; absence means a clean scan, which
                        # is the expected result against a non-vulnerable target.
                        output_json = "%s/%s-outputs/tool_import_json" % (
                            output_dir, self.TOOL_NAME
                        )

                        if os.path.exists(output_json):
                            import_arr = []
                            with open(output_json, 'r') as import_fd:
                                for line in import_fd:
                                    line = line.strip()
                                    if not line:
                                        continue
                                    import_arr.extend(json.loads(line))

                            # Verify all found vulnerabilities have the correct name
                            if import_arr:
                                scan_data_obj = {'obj_list': import_arr}
                                scan_data_inst = ScanData(scan_data_obj)

                                vuln_map = scan_data_inst.vulnerability_map
                                for vuln in vuln_map.values():
                                    assert vuln.name == 'sql_injection'

        finally:
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)

    def test_sqlmap_parse_output_with_vuln(self):
        """
        Unit-test parse_sqlmap_output directly using mock files.

        Creates a manifest JSON and two per-URL stdout captures entirely on disk
        inside a temp directory — one that contains sqlmap's injection-found
        markers and one that is clean — then asserts that exactly one Vuln
        record is returned with the expected fields.
        """
        port_id = 'c14918af17294944bf8db41f0ec1dc63'
        tool_instance_id = 'aabbccddeeff00112233445566778899'

        with tempfile.TemporaryDirectory() as tmpdir:
            # --- vulnerable URL output file ---
            vuln_output_path = os.path.join(tmpdir, 'sqlmap_out_vuln')
            with open(vuln_output_path, 'w') as f:
                f.write(SQLMAP_VULN_OUTPUT)

            # --- clean URL output file ---
            clean_output_path = os.path.join(tmpdir, 'sqlmap_out_clean')
            with open(clean_output_path, 'w') as f:
                f.write(SQLMAP_CLEAN_OUTPUT)

            # --- manifest file ---
            manifest = {
                'url_to_id_map': {
                    'https://vulnerable.example.com/page?id=1': {
                        'port_id': port_id,
                        'host_id': 'eb45abca98834ad4a525dac9a6879141',
                        'output_file': vuln_output_path,
                    },
                    'https://clean.example.com/': {
                        'port_id': port_id,
                        'host_id': 'eb45abca98834ad4a525dac9a6879142',
                        'output_file': clean_output_path,
                    },
                }
            }
            manifest_path = os.path.join(tmpdir, 'sqlmap_outputs_test')
            with open(manifest_path, 'w') as f:
                json.dump(manifest, f)

            # --- run parser ---
            results = parse_sqlmap_output(manifest_path, tool_instance_id)

            # Exactly one vulnerability should be found (the vulnerable URL only)
            assert len(results) == 1

            vuln = results[0]
            assert vuln.name == 'sql_injection'
            assert vuln.collection_tool_instance_id == tool_instance_id
            assert vuln.parent.id == port_id

            # vuln_details should capture the injection-point summary block
            assert 'identified the following injection point' in vuln.vuln_details
            assert 'Parameter: id (GET)' in vuln.vuln_details
            assert 'boolean-based blind' in vuln.vuln_details
            assert 'time-based blind' in vuln.vuln_details

    def test_sqlmap_parse_output_no_vuln(self):
        """
        Unit-test parse_sqlmap_output returns empty list when no injection found.
        """
        port_id = 'c14918af17294944bf8db41f0ec1dc63'

        with tempfile.TemporaryDirectory() as tmpdir:
            clean_output_path = os.path.join(tmpdir, 'sqlmap_out_clean')
            with open(clean_output_path, 'w') as f:
                f.write(SQLMAP_CLEAN_OUTPUT)

            manifest = {
                'url_to_id_map': {
                    'https://clean.example.com/': {
                        'port_id': port_id,
                        'host_id': 'eb45abca98834ad4a525dac9a6879141',
                        'output_file': clean_output_path,
                    },
                }
            }
            manifest_path = os.path.join(tmpdir, 'sqlmap_outputs_test')
            with open(manifest_path, 'w') as f:
                json.dump(manifest, f)

            results = parse_sqlmap_output(manifest_path)

            assert results == []

    def test_sqlmap_parse_output_missing_stdout_file(self):
        """
        Unit-test parse_sqlmap_output gracefully skips entries whose
        per-URL stdout file does not exist (e.g. process was killed).
        """
        port_id = 'c14918af17294944bf8db41f0ec1dc63'

        with tempfile.TemporaryDirectory() as tmpdir:
            manifest = {
                'url_to_id_map': {
                    'https://example.com/': {
                        'port_id': port_id,
                        'host_id': 'eb45abca98834ad4a525dac9a6879141',
                        'output_file': os.path.join(tmpdir, 'does_not_exist'),
                    },
                }
            }
            manifest_path = os.path.join(tmpdir, 'sqlmap_outputs_test')
            with open(manifest_path, 'w') as f:
                json.dump(manifest, f)

            results = parse_sqlmap_output(manifest_path)

            # Should silently skip and return empty list rather than raising
            assert results == []
