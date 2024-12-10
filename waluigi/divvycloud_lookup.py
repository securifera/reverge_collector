# DEPRECATED - This module needs updating and our team no longer has an API key to test with
# import json
# import os
# import luigi
# import multiprocessing
# import traceback
# import requests
# import netaddr
# import socket

# from luigi.util import inherits
# from tqdm import tqdm
# from multiprocessing.pool import ThreadPool
# from waluigi import scan_utils
# from waluigi import data_model

# proxies = None
# requests.packages.urllib3.disable_warnings()

# # Get Resources


# class Divvycloud(data_model.WaluigiTool):

#     def __init__(self):
#         self.name = 'divvycloud'
#         self.collector_type = data_model.CollectorType.PASSIVE.value
#         self.scan_order = 1
#         self.args = ""
#         self.import_func = Divvycloud.divvycloud_import

#     @staticmethod
#     def divvycloud_import(scan_input):
#         luigi_run_result = luigi.build([ImportDivyCloudOutput(
#             scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
#         if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
#             return False
#         return True


# # Get Resources
# def resource_query(base_url, resource_type, headers, offset=0):
#     data = {'limit': 100, 'selected_resource_type': resource_type, 'offset': offset}

#     resource_map = None
#     response = None
#     try:
#         response = requests.post(
#             url=base_url + '/v2/public/resource/query',
#             data=json.dumps(data),
#             verify=False,
#             headers=headers,
#             proxies=proxies
#         )
#     except Exception as e:
#         print(traceback.format_exc())

#     if response is not None:
#         try:
#             resource_map = response.json()
#         except Exception as e:
#             print(traceback.format_exc())
#     else:
#         print("[-] No response received")

#     return resource_map

# # Records


# def dns_records(base_url, resource_id, headers):

#     record_map = None
#     response = None
#     try:
#         response = requests.post(
#             url=base_url + '/v2/public/dnszone/%s/dnsrecords/list' % resource_id,
#             verify=False,
#             headers=headers,
#             proxies=proxies
#         )
#     except Exception as e:
#         print(traceback.format_exc())

#     if response is not None:
#         try:
#             record_map = response.json()
#         except Exception as e:
#             print(traceback.format_exc())
#     else:
#         print("[-] No response received")

#     return record_map


# def get_dnszone_resource_ids(base_url, headers):
#     resource_type = 'dnszone'
#     offset = 0
#     resource_id_set = set()
#     while True:
#         # Fetch dnszone resources
#         result_dict = resource_query(base_url, resource_type, headers, offset)
#         if result_dict:
#             # Get resources array
#             if 'resources' in result_dict:
#                 resources = result_dict['resources']
#                 resource_count = len(resources)
#                 # print("[+] Resources: %d" % len(resource_count))
#                 if resource_count == 0:
#                     break

#                 for resource in resources:
#                     dnszone = resource['dnszone']
#                     common = dnszone['common']
#                     domain = dnszone['domain']

#                     # Add resource id to the set
#                     resource_id = common['resource_id']
#                     resource_id_set.add(resource_id)
#             else:
#                 print('[-] No resources in response')
#                 print(result_dict)
#                 break
#         else:
#             print('[-] No query response')
#             break

#         # Iterate 100 records
#         offset += 100

#     else:
#         print("[-] No dnszones found")

#     return resource_id_set


# def get_dns_for_resource_id(base_url, resource_id, headers):

#     ret_dict_list = []
#     record_dict = dns_records(base_url, resource_id, headers)
#     if record_dict:
#         records = record_dict['dnsrecords']
#         for record in records:
#             dns_type = record['record_type']
#             dns_data = record['data']
#             if dns_type == 'A':
#                 common = record['common']
#                 dns_name = common['resource_name'].strip(".")

#                 # Filter out non IPv4 addresses and private IP addresses
#                 try:
#                     net_inst = netaddr.IPAddress(dns_data.strip())
#                 except:
#                     try:
#                         ip_addr = socket.gethostbyname(dns_name)
#                         net_inst = netaddr.IPAddress(ip_addr.strip())
#                         dns_data = ip_addr
#                     except:
#                         # msg = str(traceback.format_exc())
#                         # print("[-] Error resolving %s: %s" % (dns_name, msg))
#                         continue

#                 # Skip private IPs
#                 if net_inst.is_private():
#                     continue

#                 ret_dict_list.append({'domain': dns_name, 'ip_addr': dns_data})

#             elif dns_type == 'CNAME':

#                 common = record['common']
#                 dns_name = common['resource_name'].strip(".")

#                 try:
#                     ip_addr = socket.gethostbyname(dns_name)
#                     net_inst = netaddr.IPAddress(ip_addr.strip())
#                 except:
#                     # msg = str(traceback.format_exc())
#                     # print("[-] Error resolving %s: %s" % (dns_name, msg))
#                     continue

#                 # Skip private IPs
#                 if net_inst.is_private():
#                     # print("[*] IP %s is private. Skipping" % ip_addr)
#                     continue

#                 ret_dict_list.append({'domain': dns_name, 'ip_addr': ip_addr})
#     else:
#         print("[-] No records for resource %s" % resource_id)

#     return ret_dict_list


# class DivyCloudLookup(luigi.Task):

#     scan_input = luigi.Parameter()

#     def output(self):

#         scan_input_obj = self.scan_input
#         scan_id = scan_input_obj.scan_id

#         # Init directory
#         tool_name = scan_input_obj.current_tool.name
#         dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)

#         # path to input file
#         http_outputs_file = dir_path + os.path.sep + "divvycloud_outputs_" + scan_id
#         return luigi.LocalTarget(http_outputs_file)

#     def run(self):

#         scan_input_obj = self.scan_input
#         scan_target_dict = scan_input_obj.scan_target_dict

#         # Get output file path
#         output_file_path = self.output().path
#         output_file_list = []

#         if scan_target_dict:

#             # scan_input_data = scan_target_dict['scan_input']
#             # print(scan_input_data)
#             base_url = None
#             resource_type = None
#             api_key = None

#             # Get API key
#             if 'api_key' in scan_target_dict:
#                 api_key = scan_target_dict['api_key']
#             else:
#                 print("[-] No API key. Aborting.")
#                 return

#             # Assume json object here for simplicity
#             tool_args = scan_target_dict['tool_args']
#             # print(tool_args)
#             for idx in range(len(tool_args)):
#                 arg_val = tool_args[idx]
#                 if arg_val == "-u":
#                     if len(tool_args) > idx + 1:
#                         base_url = tool_args[idx + 1]
#                 elif arg_val == "-r":
#                     if len(tool_args) > idx + 1:
#                         resource_type = tool_args[idx + 1]

#             if base_url is None:
#                 print("[-] No Base URL. Aborting.")
#                 return

#             if resource_type is None:
#                 print("[-] No resource type given. Aborting.")
#                 return

#             # Set headers
#             headers = {
#                 'Content-Type': 'application/json;charset=UTF-8',
#                 'Accept': 'application/json',
#                 'Api-Key': api_key
#             }

#             # Currently only supports DNS
#             if resource_type.lower() == 'dns':
#                 resource_id_list = get_dnszone_resource_ids(base_url, headers)

#                 # Run threaded
#                 pool = ThreadPool(processes=10)
#                 thread_list = []

#                 # Add the url
#                 for resource_id in resource_id_list:
#                     thread_list.append(pool.apply_async(
#                         get_dns_for_resource_id, (base_url, resource_id, headers)))

#                 # Close the pool
#                 pool.close()

#                 # Loop through thread function calls and update progress
#                 for thread_obj in tqdm(thread_list):
#                     ret_list = thread_obj.get()
#                     if len(ret_list) > 0:
#                         output_file_list.extend(ret_list)

#         results_dict = {'output_list': output_file_list}

#         # Write output file
#         with open(output_file_path, 'w') as file_fd:
#             file_fd.write(json.dumps(results_dict))


# @inherits(DivyCloudLookup)
# class ImportDivyCloudOutput(luigi.Task):

#     def requires(self):
#         # Requires DivyCloudLookup Task to be run prior
#         return DivyCloudLookup(scan_input=self.scan_input)

#     def run(self):

#         scan_input_obj = self.scan_input
#         scan_id = scan_input_obj.scan_id
#         recon_manager = scan_input_obj.scan_thread.recon_manager

#         http_output_file = self.input().path
#         with open(http_output_file, 'r') as file_fd:
#             data = file_fd.read()

#         if len(data) > 0:

#             scan_data_dict = json.loads(data)
#             port_arr = []
#             # print(scan_data_dict)

#             # Get data and map
#             output_list = scan_data_dict['output_list']
#             if len(output_list) > 0:

#                 ip_map = {}
#                 # Convert from domain to ip map to ip to domain map
#                 for dns_entry in output_list:

#                     # Get IP for domain
#                     domain_str = dns_entry['domain']
#                     ip_str = dns_entry['ip_addr']

#                     if ip_str in ip_map:
#                         domain_list = ip_map[ip_str]
#                     else:
#                         domain_list = set()
#                         ip_map[ip_str] = domain_list

#                     domain_list.add(domain_str)

#                 port_arr = []
#                 for ip_addr in ip_map:

#                     domain_set = ip_map[ip_addr]
#                     domains = list(domain_set)

#                     ip_addr_int = int(netaddr.IPAddress(ip_addr))
#                     # print(domains)
#                     port_obj = {'ipv4_addr': ip_addr_int, 'domains': domains}

#                     # Add to list
#                     port_arr.append(port_obj)

#             if len(port_arr) > 0:
#                 # print(port_arr)

#                 # Import the ports to the manager
#                 tool_obj = scan_input_obj.current_tool
#                 tool_id = tool_obj.id
#                 scan_results = {'tool_id': tool_id,
#                                 'scan_id': scan_id, 'port_list': port_arr}

#                 # print(scan_results)
#                 ret_val = recon_manager.import_ports_ext(scan_results)
#                 print("[+] Imported divvy cloud scan to manager.")

#             else:
#                 print("[*] No ports to import to manager")
