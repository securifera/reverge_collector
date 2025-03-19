from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from types import SimpleNamespace
from threading import Event
from waluigi import scan_cleanup, scan_utils
from waluigi import data_model
from collections import OrderedDict
from functools import partial

import requests
import base64
import binascii
import json
import threading
import traceback
import os
import netifaces
import enum
import functools
import logging
import luigi
import zlib


logger = logging.getLogger(__name__)

# User Agent
custom_user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"

# Set to bypass errors if the target site has SSL issues
requests.packages.urllib3.disable_warnings()
recon_mgr_inst = None


class SessionException(Exception):
    def __init__(self, message="Unable to get session token"):
        super().__init__(message)


def tool_order_cmp(x, y):

    if x.collection_tool.scan_order is None:
        return -1

    if y.collection_tool.scan_order is None:
        return 1

    if x.collection_tool.scan_order > y.collection_tool.scan_order:
        return 1
    elif x.collection_tool.scan_order < y.collection_tool.scan_order:
        return -1
    else:
        return 0


def encrypt_data(session_key, data):

    compressed_data = zlib.compress(data)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(compressed_data)
    packet = cipher_aes.nonce + tag + ciphertext
    b64_data = base64.b64encode(packet).decode()

    return b64_data


class DictQueue:
    def __init__(self):
        self.queue = OrderedDict()

    def enqueue(self, key, value):
        if key not in self.queue:
            self.queue[key] = value
        else:
            logger.debug("Key already exists in queue.")

    def get_next(self):
        if self.queue:
            first_key = next(iter(self.queue))
            return first_key, self.queue[first_key]
        return None

    def remove(self, key):
        if key in self.queue:
            del self.queue[key]

    def __contains__(self, key):
        return key in self.queue

    def __len__(self):
        return len(self.queue)


class ScanStatus(enum.Enum):
    CREATED = 1
    RUNNING = 2
    COMPLETED = 3
    CANCELLED = 4
    ERROR = 5

    def __str__(self):
        if (self == ScanStatus.CREATED):
            return "CREATED"
        elif (self == ScanStatus.RUNNING):
            return "RUNNING"
        elif (self == ScanStatus.COMPLETED):
            return "COMPLETED"
        elif (self == ScanStatus.CANCELLED):
            return "CANCELLED"
        elif (self == ScanStatus.ERROR):
            return "ERROR"


class CollectionToolStatus(enum.Enum):
    CREATED = 1
    RUNNING = 2
    COMPLETED = 3
    ERROR = 4

    def __str__(self):
        if (self == CollectionToolStatus.CREATED):
            return "CREATED"
        elif (self == CollectionToolStatus.RUNNING):
            return "RUNNING"
        elif (self == CollectionToolStatus.COMPLETED):
            return "COMPLETED"
        elif (self == CollectionToolStatus.ERROR):
            return "ERROR"


class ScheduledScan():

    def __init__(self, scheduled_scan_thread, scheduled_scan):
        self.scan_thread = scheduled_scan_thread
        self.target_id = scheduled_scan.target_id
        self.scan_id = scheduled_scan.scan_id
        self.id = scheduled_scan.id

        self.collection_tool_map = {}
        for collection_tool in scheduled_scan.collection_tools:

            wordlist_path = None
            # Only get wordlists for enabled tools
            if collection_tool.enabled == 1:
                # Prepare wordlist if present
                worlist_arr = []
                for wordlist in collection_tool.collection_tool.wordlists:
                    wordlist_id = wordlist.id
                    wordlist_hash = wordlist.hash
                    wordlist_json = None

                    # Check in path wordlist_path to see if a file exists
                    file_path = os.path.join(
                        data_model.wordlist_path, str(wordlist_id))
                    if not os.path.exists(file_path):
                        wordlist_json = self.scan_thread.recon_manager.get_wordlist(
                            wordlist_id)
                        with open(file_path, 'w') as f:
                            json.dump(wordlist_json, f)

                    else:
                        try:
                            with open(file_path, 'r') as f:
                                wordlist_json = json.load(f)

                            if 'hash' in wordlist_json:
                                if wordlist_json['hash'] != wordlist_hash:
                                    wordlist_json = self.scan_thread.recon_manager.get_wordlist(
                                        wordlist_id)
                                    with open(file_path, 'w') as f:
                                        json.dump(wordlist_json, f)
                            else:
                                raise Exception("No hash field")

                        except:
                            os.remove(file_path)
                            wordlist_json = self.scan_thread.recon_manager.get_wordlist(
                                wordlist_id)
                            with open(file_path, 'w') as f:
                                json.dump(wordlist_json, f)

                    # Add words to wordlist
                    if wordlist_json and 'words' in wordlist_json:
                        worlist_arr.extend(wordlist_json['words'])

                # Prepare wordlist for scan
                if len(worlist_arr) > 0:
                    wordlist_path = os.path.join(
                        data_model.wordlist_path, str(collection_tool.id))
                    with open(wordlist_path, 'w') as f:
                        f.write("\n".join(worlist_arr) + "\n")

            # Add to map
            collection_tool.collection_tool.wordlist_path = wordlist_path
            self.collection_tool_map[collection_tool.id] = collection_tool

        self.current_tool = None
        self.selected_interface = None

        # Create a scan id if it does not exist
        scan_obj = self.scan_thread.recon_manager.get_scheduled_scan(
            self.id)
        if scan_obj is None or 'scan_id' not in scan_obj or scan_obj['scan_id'] is None:
            raise RuntimeError(
                "[-] No scan object returned for scheduled scan.")
        else:
            self.scan_id = scan_obj['scan_id']

        # Get scope
        if 'scope' not in scan_obj or scan_obj['scope'] is None:
            raise RuntimeError(
                "[-] No scan scope returned for scheduled scan.")

        scope_dict = scan_obj['scope']
        self.scan_data = data_model.ScanData(
            scope_dict, record_tags=set([data_model.RecordTag.REMOTE.value]))

        # Get the selected network interface
        if 'interface' in scan_obj and scan_obj['interface']:
            self.selected_interface = scope_dict = scan_obj['interface']

        # Update scan status to running
        self.update_scan_status(ScanStatus.RUNNING.value)

    # Update the scan status
    def update_scan_status(self, scan_status, err_msg=None):
        # Send update to the server
        self.scan_thread.recon_manager.update_scan_status(
            self.id, scan_status)

    def update_tool_status(self, tool_id, tool_status, tool_status_msg=''):
        # Send update to the server
        self.scan_thread.recon_manager.update_tool_status(
            tool_id, tool_status, tool_status_msg)

        # Update in collection tool map
        if tool_id in self.collection_tool_map:
            tool_obj = self.collection_tool_map[tool_id]
            tool_obj.status = tool_status

    def cleanup(self):

        collection_tools = self.collection_tool_map.values()
        for collection_tool_inst in collection_tools:
            # Remove the wordlist file
            if collection_tool_inst.collection_tool.wordlist_path and os.path.exists(collection_tool_inst.collection_tool.wordlist_path):
                os.remove(collection_tool_inst.collection_tool.wordlist_path)

    # This is necessary because luigi hashes input parameters and dictionaries won't work
    def __hash__(self):
        return 0


class ScheduledScanThread(threading.Thread):

    # Static variable to hold luigi exceptions
    failed_task_exception = None

    def __init__(self, recon_manager, connection_manager=None):
        threading.Thread.__init__(self)
        self._is_running = False
        self._daemon = True
        self._enabled = True
        self.recon_manager = recon_manager
        self.connection_manager = connection_manager
        self.exit_event = Event()
        self.checkin_interval = 60
        self.scan_queue = DictQueue()
        self.current_scan_thread_future = None
        self.log_queue = None

    # Event handler to catch luigi task failures
    @luigi.Task.event_handler(luigi.Event.FAILURE)
    def catch_failure(task, exception):
        ScheduledScanThread.failed_task_exception = (task, exception)

    def toggle_poller(self):

        if self._enabled:
            self._enabled = False
            logger.debug("Scan poller disabled.")
        else:
            self._enabled = True
            logger.debug("Scan poller enabled.")

    def execute_scan_jobs(self, scheduled_scan_obj: ScheduledScan):

        err_msg = None
        # Set connection target in connection manager to this target
        target_id = scheduled_scan_obj.target_id
        self.recon_manager.set_current_target(
            self.connection_manager, target_id)

        # Sort the list
        collection_tools = scheduled_scan_obj.collection_tool_map.values()
        sorted_list = sorted(collection_tools,
                             key=functools.cmp_to_key(tool_order_cmp))

        # Connect to extender to see if scan has been cancelled and get tool scope
        if self.connection_manager and self.connection_manager.connect_to_extender() == False:
            err_msg = "Failed connecting to extender"
            logger.error(err_msg)
            return err_msg

        ret_status = None
        for collection_tool_inst in sorted_list:

            # Return value for tool
            try:
                ret_status = CollectionToolStatus.RUNNING.value

                tool_obj = collection_tool_inst.collection_tool

                # Skip any tools that don't have a scan order
                if tool_obj.scan_order == None or collection_tool_inst.enabled == 0:
                    continue

                if collection_tool_inst.args_override:
                    tool_obj.args = collection_tool_inst.args_override

                # Set the tool obj
                scheduled_scan_obj.current_tool = tool_obj

                # Check if scan is cancelled
                scan_status = self.recon_manager.get_scan_status(
                    scheduled_scan_obj.scan_id)
                if scan_status is None or scan_status == ScanStatus.CANCELLED.value:
                    err_msg = "Scan cancelled or doesn't exist"
                    logger.debug(err_msg)
                    return err_msg

                # Check if load balanced
                # skip_load_balance_ports = self.recon_manager.is_load_balanced()

                # If the tool is active then connect to the target and run the scan
                if tool_obj.tool_type == 2:

                    if self.connection_manager and self.connection_manager.connect_to_target() == False:
                        err_msg = "Failed connecting to target"
                        logger.error(err_msg)
                        return err_msg

                    try:

                        # Update to running
                        scheduled_scan_obj.update_tool_status(
                            collection_tool_inst.id, CollectionToolStatus.RUNNING.value)

                        # Execute scan func
                        if self.recon_manager.scan_func(scheduled_scan_obj) == False:
                            err_msg = "Scan function failed"
                            logger.debug(err_msg)
                            ret_status = CollectionToolStatus.ERROR.value
                            break

                    except Exception as e:
                        err_msg = "Error calling scan function: %s" % str(e)
                        logger.error(err_msg)
                        logger.debug(traceback.format_exc())
                        ret_status = CollectionToolStatus.ERROR.value
                        break
                    finally:

                        err_msg = ''
                        if ScheduledScanThread.failed_task_exception:
                            err_msg = f"{ScheduledScanThread.failed_task_exception[0]}\n{ScheduledScanThread.failed_task_exception[1]}"
                            ScheduledScanThread.failed_task_exception = None

                        scheduled_scan_obj.update_tool_status(
                            collection_tool_inst.id, ret_status, err_msg)
                        if self.connection_manager and self.connection_manager.connect_to_extender() == False:
                            err_msg = "Failed connecting to extender"
                            logger.error(err_msg)
                            return err_msg

                # Import results
                try:
                    if self.recon_manager.import_func(scheduled_scan_obj) == False:
                        err_msg = "Import function failed"
                        logger.debug(err_msg)
                        ret_status = CollectionToolStatus.ERROR.value
                        break
                    else:
                        ret_status = CollectionToolStatus.COMPLETED.value
                except Exception as e:
                    err_msg = "Error calling import function: %s" % str(e)
                    logger.error(err_msg)
                    logger.debug(traceback.format_exc())
                    ret_status = CollectionToolStatus.ERROR.value
                    break

                finally:

                    err_msg = None
                    if ScheduledScanThread.failed_task_exception:
                        err_msg = f"{ScheduledScanThread.failed_task_exception[0]}\n{ScheduledScanThread.failed_task_exception[1]}"
                        ScheduledScanThread.failed_task_exception = None

                    scheduled_scan_obj.update_tool_status(
                        collection_tool_inst.id, ret_status, err_msg)

            finally:
                # Reset the current tool variable
                scheduled_scan_obj.current_tool = None

        # Cleanup files
        if ret_status == CollectionToolStatus.COMPLETED.value:
            scan_cleanup.scan_cleanup_func(scheduled_scan_obj.scan_id)
            err_msg = None

        return err_msg

    def process_collector_settings(self, collector_settings):

        try:

            if 'poll_interval' in collector_settings:
                poll_interval = int(collector_settings['poll_interval'])
                if self.checkin_interval != poll_interval and poll_interval > 0 and poll_interval < 3600:
                    # Set the poll interval
                    self.checkin_interval = poll_interval

        except Exception as e:
            logger.error("Error: %s" % str(e))
            logger.debug(traceback.format_exc())

    def process_scan_obj(self, sched_scan_obj):

        # Create scan object
        err_msg = None
        scheduled_scan_obj = ScheduledScan(self, sched_scan_obj)

        # Execute scan jobs
        scan_status = ScanStatus.ERROR.value
        try:
            err_msg = self.execute_scan_jobs(scheduled_scan_obj)

            # Set status
            if self.connection_manager and self.connection_manager.connect_to_extender() == False:
                logger.error("Failed connecting to extender")
                return False

            if err_msg is None:
                # Update scan status
                scan_status = ScanStatus.COMPLETED.value

        except Exception as e:
            logger.error("Error executing scan job")
            logger.debug(traceback.format_exc())

        # Update scan status
        scheduled_scan_obj.update_scan_status(scan_status)
        # Remove temporary files
        scheduled_scan_obj.cleanup()
        # Set thread future to None
        self.scan_queue.remove(sched_scan_obj.id)

        # self.current_scan_thread_future = None

        return

    def run(self):

        if not self._is_running:

            # Check that the recon manager object exists
            recon_manager = self.recon_manager
            if recon_manager:

                # Set running flag
                self._is_running = True
                while self._is_running:

                    self.exit_event.wait(self.checkin_interval)
                    if self._enabled:
                        # logger.debug("Checking for any scheduled scans")
                        lock_val = None
                        try:

                            if self.connection_manager:
                                lock_val = self.connection_manager.get_connection_lock()
                                if lock_val:
                                    ret_val = self.connection_manager.connect_to_extender()
                                    if ret_val == False:
                                        logger.error(
                                            "Failed connecting to extender")
                                        continue
                                else:
                                    logger.debug(
                                        "Connection lock is currently held. Retrying later")
                                    continue

                            result_str = None
                            result_list = []
                            while not self.log_queue.empty() and len(result_list) < 100:
                                result_list.append(
                                    self.log_queue.get())
                            if len(result_list) > 0:
                                result_str = "\n".join(result_list)

                            # Update any collector settings
                            collector_settings = recon_manager.collector_poll(
                                result_str)
                            if collector_settings:
                                self.process_collector_settings(
                                    collector_settings)

                            sched_scan_obj_arr = recon_manager.get_scheduled_scans()
                            for sched_scan_obj in sched_scan_obj_arr:
                                scheduled_scan_id = sched_scan_obj.id
                                if scheduled_scan_id not in self.scan_queue:
                                    self.scan_queue.enqueue(
                                        scheduled_scan_id, sched_scan_obj)

                            # Check if any of the scheduled scans have been cancelled
                            if self.current_scan_thread_future is None or self.current_scan_thread_future.done():
                                sched_scan_obj_tuple = self.scan_queue.get_next()
                                if sched_scan_obj_tuple:
                                    sched_scan_obj = sched_scan_obj_tuple[1]
                                    self.current_scan_thread_future = scan_utils.executor.submit(partial(
                                        self.process_scan_obj, sched_scan_obj))

                        except requests.exceptions.ConnectionError as e:
                            logger.error("Unable to connect to server.")
                            pass
                        except Exception as e:
                            logger.debug(traceback.format_exc())
                            pass
                        finally:
                            # Release the lock if we have it
                            if self.connection_manager:
                                if lock_val:
                                    self.connection_manager.free_connection_lock(
                                        lock_val)

    def stop(self, timeout=None):
        # Check if thread is dead
        self._is_running = False
        self.exit_event.set()


def get_recon_manager(token, manager_url):
    global recon_mgr_inst
    if recon_mgr_inst == None:
        recon_mgr_inst = ReconManager(token, manager_url)
    return recon_mgr_inst


class ReconManager:

    def __init__(self, token, manager_url):
        self.token = token
        self.debug = False
        self.manager_url = manager_url
        self.headers = {'User-Agent': custom_user_agent,
                        'Authorization': 'Bearer ' + self.token}
        self.session_key = self._get_session_key()

        # Get network interfaces
        self.network_ifaces = self.get_network_interfaces()

        # Tool map
        self.waluigi_tool_map = {}
        tool_classes = data_model.get_tool_classes()

        tool_name_inst_map = {}
        for tool_class in tool_classes:
            tool_inst = tool_class()
            # self.register_tool(tool_class)
            tool_name_inst_map[tool_inst.name] = tool_inst

        # Send collector data to server
        collector_tools = []
        # tool_map = self.waluigi_tool_map
        for tool_obj in tool_name_inst_map.values():
            collector_tools.append(tool_obj.to_jsonable())

        collector_data = {
            'interfaces': self.network_ifaces, 'tools': collector_tools}

        # Send interfaces & tools
        ret_obj = self.update_collector(collector_data)
        if ret_obj:
            # logger.debug("Collector data: %s" % ret_obj)
            if 'tool_name_id_map' in ret_obj:
                tool_name_id_map = ret_obj['tool_name_id_map']
                if len(tool_name_id_map) > 0:
                    for tool_name in tool_name_id_map:
                        tool_id = tool_name_id_map[tool_name]
                        tool_id_hex = format(int(tool_id), 'x')
                        if tool_name in tool_name_inst_map:
                            self.waluigi_tool_map[tool_id_hex] = tool_name_inst_map[tool_name]
                        else:
                            logger.debug(
                                "%s tool not found in tool name instance map." % tool_name)
                    return

        raise SessionException()

    def get_tool_map(self):
        return self.waluigi_tool_map

    def scan_func(self, scan_input: ScheduledScan):

        # Get the tool
        ret_val = False
        tool_obj = scan_input.current_tool
        tool_id = tool_obj.id
        if tool_id in self.waluigi_tool_map:
            tool_inst = self.waluigi_tool_map[tool_id]

            # Call the scan function
            ret_val = tool_inst.scan_func(scan_input)

        else:
            logger.debug("%s tool does not exist in table." % tool_id)

        return ret_val

    def import_func(self, scan_input: ScheduledScan):

        ret_val = False
        # Get the tool
        tool_obj = scan_input.current_tool
        tool_id = tool_obj.id
        if tool_id in self.waluigi_tool_map:
            tool_inst = self.waluigi_tool_map[tool_id]

            # Call the scan function
            ret_val = tool_inst.import_func(scan_input)

        else:
            logger.debug(f"Error: {tool_id} tool does not exist in table.")

        return ret_val

    def get_network_interfaces(self):

        interface_dict = {}
        ifaces = netifaces.interfaces()
        for if_name in ifaces:
            loop_back = False
            addrs = netifaces.ifaddresses(if_name)

            # Get the IP address
            if netifaces.AF_INET in addrs:

                ipv4_addr_arr = addrs[netifaces.AF_INET]
                for ipv4_obj in ipv4_addr_arr:

                    ip_str = ipv4_obj['addr']
                    netmask = ipv4_obj['netmask']

                    if ip_str == "127.0.0.1":
                        loop_back = True

                    # Only get the first one
                    break
            else:
                # If there's no IP address we don't care
                continue

            # Skip if it's loopback
            if loop_back:
                continue

            if netifaces.AF_LINK in addrs:

                hardware_addr_arr = addrs[netifaces.AF_LINK]
                for hardware_addr_obj in hardware_addr_arr:
                    mac_addr_str = hardware_addr_obj['addr']

                    # Only get the first one
                    break

            interface_dict[if_name] = {
                'ipv4_addr': ip_str, 'netmask': netmask, 'mac_address': mac_addr_str}

        return interface_dict

    # Stub to be overwritten in case anything needs to be done by a specific connection manager
    # in regards to the target specified

    def set_current_target(self, connection_manager, target_id):
        return

    # Stub to be overwritten if the recon manager is behind a load balancer (some ports always return up)
    def is_load_balanced(self):
        return False

    def _decrypt_json(self, content):

        data = None
        if 'data' in content:
            b64_data = content['data']
            enc_data = base64.b64decode(b64_data)

            nonce = enc_data[:16]
            # print("[*] Nonce: %s" % binascii.hexlify(nonce).decode())
            tag = enc_data[16:32]
            # print("[*] Sign: %s" % binascii.hexlify(tag).decode())
            ciphertext = enc_data[32:]

            cipher_aes = AES.new(self.session_key, AES.MODE_EAX, nonce)
            try:
                compressed_data = cipher_aes.decrypt_and_verify(
                    ciphertext, tag)
                data = zlib.decompress(compressed_data)
            except Exception as e:
                logger.error("Error decrypting response: %s" % str(e))

                # Attempting to decrypt from the session key on disk
                session_key = self._get_session_key_from_disk()
                if session_key and session_key != self.session_key:
                    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
                    try:
                        compressed_data = cipher_aes.decrypt_and_verify(
                            ciphertext, tag)
                        data = zlib.decompress(compressed_data)
                        self.session_key = session_key
                        return data
                    except Exception as e:
                        logger.error(
                            "Error decrypting response with session from disk. Refreshing session: %s" % str(e))

                # Remove the previous session file
                os.remove('session')

                # Attempt to get a new session token
                self.session_key = self._get_session_key()

        return data

    def _get_session_key_from_disk(self):

        session_key = None
        if os.path.exists('session'):

            with open("session", "r") as file_fd:
                hex_session = file_fd.read().strip()

            # logger.debug("Session Key File Exists. Key: %s" % hex_session)

            session_key = binascii.unhexlify(hex_session)

        return session_key

    def _get_session_key(self):

        session_key = self._get_session_key_from_disk()
        if session_key:
            return session_key

        # Generate temp RSA keys to encrypt session key
        key = RSA.generate(2048)
        private_key = key.export_key(format='DER')
        # print("Length: %d" % len(private_key))
        public_key = key.publickey().export_key(format='DER')

        session_key = None
        b64_val = base64.b64encode(public_key).decode()
        r = requests.post('%s/api/session' % self.manager_url, headers=self.headers, json={"data": b64_val},
                          verify=False)
        if r.status_code != 200:
            logger.error("Error retrieving session key.")
            raise SessionException()

        if r.content:
            ret_json = r.json()
            if "data" in ret_json:
                b64_session_key = ret_json['data']
                enc_session_key = base64.b64decode(b64_session_key)

                # Decrypt the session key with the private RSA key
                private_key_obj = RSA.import_key(private_key)
                cipher_rsa = PKCS1_OAEP.new(private_key_obj)
                session_key = cipher_rsa.decrypt(enc_session_key)

                with open(os.open('session', os.O_CREAT | os.O_WRONLY, 0o777), 'w') as fh:
                    fh.write(binascii.hexlify(session_key).decode())

        return session_key

    def get_subnets(self, scan_id):

        subnets = []
        r = requests.get('%s/api/subnets/scan/%s' % (self.manager_url,
                         scan_id), headers=self.headers, verify=False)
        if r.status_code == 404:
            return subnets
        if r.status_code != 200:
            logger.error("Unknown Error retriving subnets")
            return subnets

        if r.content:
            subnet_obj_arr = None
            try:
                content = r.json()
                data = self._decrypt_json(content)
                subnet_obj_arr = json.loads(
                    data, object_hook=lambda d: SimpleNamespace(**d))
            except Exception as e:
                logger.error("Error retrieving subnets: %s" % str(e))
                logger.debug(traceback.format_exc())
                return subnets

            if subnet_obj_arr:
                for subnet in subnet_obj_arr:
                    ip = subnet.subnet
                    subnet_inst = ip + "/" + str(subnet.mask)
                    subnets.append(subnet_inst)

        return subnets

    def get_wordlist(self, wordlist_id):

        wordlist = None
        r = requests.get('%s/api/wordlist/%s' % (self.manager_url,
                         wordlist_id), headers=self.headers, verify=False)
        if r.status_code == 404:
            return wordlist
        if r.status_code != 200:
            logger.error("Unknown Error retrieving wordlist")
            return wordlist

        if r.content:
            try:
                content = r.json()
                data = self._decrypt_json(content)
                wordlist = json.loads(data)
            except Exception as e:
                logger.error("Error retrieving wordlist: %s" % str(e))
                logger.debug(traceback.format_exc())
                return wordlist

        return wordlist

    def get_target(self, scan_id):

        target_obj = None
        r = requests.get('%s/api/target/scan/%s' % (self.manager_url,
                         scan_id), headers=self.headers, verify=False)
        if r.status_code == 404:
            return target_obj
        if r.status_code != 200:
            logger.error("Unknown Error retrieving targets")
            return target_obj

        if r.content:
            try:
                content = r.json()
                if content:
                    data = self._decrypt_json(content)
                    target_obj = json.loads(
                        data, object_hook=lambda d: SimpleNamespace(**d))
            except Exception as e:
                logger.error("Error retrieving target: %s" % str(e))
                logger.debug(traceback.format_exc())

        return target_obj

    def get_tool_scope(self, scan_id, tool_id, load_balanced=False):

        target_obj = None
        target_url = '%s/api/scan/%s/scope/%s' % (
            self.manager_url, scan_id, tool_id)
        if load_balanced:
            target_url += "?load_balanced=True"

        r = requests.get(target_url, headers=self.headers, verify=False)
        if r.status_code == 404:
            return target_obj
        if r.status_code != 200:
            logger.error("Error retrieving tool scope.")
            return target_obj

        if r.content:
            try:
                content = r.json()
                data = self._decrypt_json(content)
                if len(data) > 0:
                    target_obj = json.loads(data)
            except Exception as e:
                logger.error("Error retrieving tool scope: %s" % str(e))
                logger.debug(traceback.format_exc())
                return target_obj

        return target_obj

    def get_urls(self, scan_id):

        urls = []
        r = requests.get('%s/api/urls/scan/%s' % (self.manager_url,
                         scan_id), headers=self.headers, verify=False)
        if r.status_code == 404:
            return urls
        if r.status_code != 200:
            logger.error("Unknown Error retrieving urls")
            return urls

        if r.content:
            url_obj_arr = None
            try:
                content = r.json()
                data = self._decrypt_json(content)
                url_obj_arr = json.loads(
                    data, object_hook=lambda d: SimpleNamespace(**d))
            except Exception as e:
                logger.error("Error retrieving urls: %s" % str(e))
                logger.debug(traceback.format_exc())
                return urls

            if url_obj_arr:
                for url_obj in url_obj_arr:
                    url = url_obj.url
                    urls.append(url)

        return urls

    def get_scheduled_scans(self):

        sched_scan_arr = []
        r = requests.get('%s/api/scheduler/' %
                         (self.manager_url), headers=self.headers, verify=False)
        if r.status_code == 404:
            return sched_scan_arr
        elif r.status_code != 200:
            logger.error("Unknown Error retrieving scheduled scans")
            return sched_scan_arr

        if r.content:
            try:
                content = r.json()
                data = self._decrypt_json(content)
                if data:
                    sched_scan_arr = json.loads(
                        data, object_hook=lambda d: SimpleNamespace(**d))
            except Exception as e:
                logger.error("Error retrieving scheduled scans: %s" % str(e))
                logger.debug(traceback.format_exc())

        return sched_scan_arr

    def collector_poll(self, log_str):

        settings = None
        status_dict = {'logs': log_str}
        json_data = json.dumps(status_dict).encode()
        b64_val = encrypt_data(self.session_key, json_data)

        r = requests.post('%s/api/collector/poll' %
                          (self.manager_url), headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code == 404:
            return settings
        elif r.status_code != 200:
            logger.error("Unknown Error retrieving collector settings")
            return settings

        if r.content:
            try:
                content = r.json()
                data = self._decrypt_json(content)
                if data:
                    settings = json.loads(data)
            except Exception as e:
                logger.error(
                    "Error retrieving collector settings: %s" % str(e))
                logger.debug(traceback.format_exc())

        return settings

    def get_scheduled_scan(self, sched_scan_id):

        sched_scan = None
        r = requests.get('%s/api/scheduler/%s/scan/' % (self.manager_url, sched_scan_id), headers=self.headers,
                         verify=False)
        if r.status_code == 404:
            return sched_scan
        elif r.status_code != 200:
            logger.error("Unknown Error retrieving scan")
            return sched_scan

        if r.content:
            try:
                content = r.json()
                data = self._decrypt_json(content)
                sched_scan = json.loads(data)
            except Exception as e:
                logger.error("Error retrieving scan: %s" % str(e))
                logger.debug(traceback.format_exc())

        return sched_scan

    def get_scan_status(self, scan_id):

        scan_status = None
        r = requests.get('%s/api/scan/%s/status' % (self.manager_url,
                         scan_id), headers=self.headers, verify=False)
        if r.status_code == 404:
            return scan_status
        elif r.status_code != 200:
            logger.error("Unknown Error retrieving scan")
            return scan_status

        if r.content:
            try:
                content = r.json()
                data = self._decrypt_json(content)
                scan_status_dict = json.loads(data)
                if 'status' in scan_status_dict:
                    scan_status = scan_status_dict['status']
            except Exception as e:
                logger.error("Error retrieving scan status: %s" % str(e))
                logger.debug(traceback.format_exc())

        return scan_status

    def get_hosts(self, scan_id):

        port_arr = []
        r = requests.get('%s/api/hosts/scan/%s' % (self.manager_url,
                         scan_id), headers=self.headers, verify=False)
        if r.status_code == 404:
            return port_arr
        elif r.status_code != 200:
            logger.error("Unknown Error retrieving hosts")
            return port_arr

        if r.content:
            try:
                content = r.json()
                data = self._decrypt_json(content)
                port_arr = json.loads(
                    data, object_hook=lambda d: SimpleNamespace(**d))
            except Exception as e:
                logger.error("Error retrieving hosts: %s" % str(e))
                logger.debug(traceback.format_exc())

        return port_arr

    def get_tools(self):

        tool_obj_arr = []
        r = requests.get('%s/api/tools' % (self.manager_url),
                         headers=self.headers, verify=False)
        if r.status_code == 404:
            return tool_obj_arr
        elif r.status_code != 200:
            logger.error("Unknown Error retrieving tools")
            return tool_obj_arr

        if r.content:
            try:
                content = r.json()
                data = self._decrypt_json(content)
                tool_obj_arr = json.loads(
                    data, object_hook=lambda d: SimpleNamespace(**d))
            except Exception as e:
                logger.error("Error retrieving tools: %s" % str(e))
                logger.debug(traceback.format_exc())

        return tool_obj_arr

    def update_collector(self, collector_data):

        # Import the data to the manager
        json_data = json.dumps(collector_data).encode()
        b64_val = encrypt_data(self.session_key, json_data)
        r = requests.post('%s/api/collector' % (self.manager_url),
                          headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error updating collector interfaces.")

        ret_obj = None
        if r.content:
            try:
                content = r.json()
                data = self._decrypt_json(content)
                ret_obj = json.loads(data)
            except Exception as e:
                logger.error("Error retrieving collector data: %s" % str(e))
                logger.debug(traceback.format_exc())

        return ret_obj

    def update_scan_status(self, schedule_scan_id, status, err_msg=None):

        # Import the data to the manager
        status_dict = {'status': status, 'error_message': err_msg}
        json_data = json.dumps(status_dict).encode()

        b64_val = encrypt_data(self.session_key, json_data)
        r = requests.post('%s/api/scheduler/%s/' % (self.manager_url, schedule_scan_id),
                          headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error updating scan status.")

        return True

    def get_tool_status(self, tool_id):

        status = None
        r = requests.get('%s/api/tool/status/%s' % (self.manager_url,
                         tool_id), headers=self.headers, verify=False)
        if r.status_code == 404:
            return status
        if r.status_code != 200:
            logger.error("Unknown Error retrieving tool status")
            return status

        if r.content:
            try:
                content = r.json()
                data = self._decrypt_json(content)
                if data:
                    tool_inst = json.loads(
                        data, object_hook=lambda d: SimpleNamespace(**d))
                    status = tool_inst.status
            except Exception as e:
                logger.error("Error retrieving tool status: %s" % str(e))
                logger.debug(traceback.format_exc())

        return status

    def update_tool_status(self, tool_id, status, status_message=''):

        # Import the data to the manager
        status_dict = {'status': status, 'status_message': status_message}
        json_data = json.dumps(status_dict).encode()

        b64_val = encrypt_data(self.session_key, json_data)
        r = requests.post('%s/api/tool/status/%s' % (self.manager_url, tool_id),
                          headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error updating tool status.")

        return True

    def import_ports(self, port_arr):

        # Import the data to the manager
        json_data = json.dumps(port_arr).encode()

        b64_val = encrypt_data(self.session_key, json_data)
        r = requests.post('%s/api/ports' % self.manager_url,
                          headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error importing ports to manager server.")

        return True

    def import_ports_ext(self, scan_results_dict):

        # Import the data to the manager
        json_data = json.dumps(scan_results_dict).encode()
        b64_val = encrypt_data(self.session_key, json_data)
        r = requests.post('%s/api/ports/ext' % self.manager_url,
                          headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error importing ports to manager server.")

        return True

    def import_data(self, scan_id, tool_id, scan_results):

        scan_results_dict = {'tool_id': tool_id,
                             'scan_id': scan_id, 'obj_list': scan_results}

        # Import the data to the manager
        json_data = json.dumps(scan_results_dict).encode()
        b64_val = encrypt_data(self.session_key, json_data)
        r = requests.post('%s/api/data/import' % self.manager_url,
                          headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error importing ports to manager server.")

        record_arr = []
        if r.content:
            try:
                content = r.json()
                data = self._decrypt_json(content)
                if data:
                    record_arr = json.loads(data)
            except Exception as e:
                logger.error("Error retrieving import response: %s" % str(e))
                logger.debug(traceback.format_exc())

        return record_arr

    def import_shodan_data(self, scan_id, shodan_arr):

        # Import the data to the manager
        json_data = json.dumps(shodan_arr).encode()
        b64_val = encrypt_data(self.session_key, json_data)
        r = requests.post('%s/api/integration/shodan/import/%s' % (self.manager_url,
                          str(scan_id)), headers=self.headers, json={"data": b64_val}, verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error importing ports to manager server.")

        return True

    def import_screenshot(self, data_dict):

        # Import the data to the manager
        obj_data = [data_dict]

        json_data = json.dumps(obj_data).encode()
        b64_val = encrypt_data(self.session_key, json_data)
        r = requests.post('%s/api/screenshots' % self.manager_url, headers=self.headers, json={"data": b64_val},
                          verify=False)
        if r.status_code != 200:
            raise RuntimeError("[-] Error importing ports to manager server.")

        return True
