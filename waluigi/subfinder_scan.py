import json
import os
import subprocess
import netaddr
import socket
import luigi
import multiprocessing
import traceback
import os.path
import yaml

from luigi.util import inherits
from multiprocessing.pool import ThreadPool
from waluigi import scan_utils


class SubfinderScope(luigi.ExternalTask):

    scan_input = luigi.Parameter()

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

         # Create input directory if it doesn't exist
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "subfinder-inputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        # path to each input file
        dns_inputs_file = dir_path + os.path.sep + "subfinder_inputs_" + scan_id
        if os.path.isfile(dns_inputs_file):
            return luigi.LocalTarget(dns_inputs_file) 

        # Create output file
        f_inputs = open(dns_inputs_file, 'w')
        
        dns_url_file = dir_path + os.path.sep + "dns_urls_" + scan_id
        url_inputs_fd = open(dns_url_file, 'w')

        scan_target_dict = scan_input_obj.scan_target_dict
        if scan_target_dict:
            
            # Write the output
            scan_input = scan_target_dict['scan_input']
            api_keys = scan_target_dict['api_keys']
            target_map = {}
            if 'target_map' in scan_input:
                target_map = scan_input['target_map']
           
            print("[+] Retrieved %d urls from database" % len(target_map))
            for target_key in target_map:
                url_inputs_fd.write(target_key + '\n')          

        else:
            print("[-] Target url list is empty.")

        # Close urls inputs file
        url_inputs_fd.close()

        # Write the output
        scan_dict = json.dumps({'input_path': dns_url_file, 'api_keys' : api_keys})
        f_inputs.write(scan_dict)

        # Close output file
        f_inputs.close()

        # Path to scan inputs
        scan_utils.add_file_to_cleanup(scan_id, dir_path)

        return luigi.LocalTarget(dns_inputs_file)

def update_config_file(api_keys):

    config_file_path = "/root/.config/subfinder/provider-config.yaml"

    # If no file then run subfinder to generate the template
    if os.path.isfile(config_file_path) == False:
        subprocess.run("subfinder -h")

    # Update provider config file
    f = open(config_file_path, 'r')
    data = yaml.safe_load(f)
    f.close()

    #print(data)
    key_arr = []
    if 'chaos' in api_keys:
        key_val = api_keys['chaos']
        key_arr.append(key_val)
    data['chaos'] = key_arr

    key_arr = []
    if 'shodan' in api_keys:
        key_val = api_keys['shodan']
        key_arr.append(key_val)
    data['shodan'] = key_arr

    key_arr = []
    if 'sectrails' in api_keys:
        key_val = api_keys['sectrails']
        key_arr.append(key_val)
    data['securitytrails'] = key_arr

    # Write to config file
    with open(config_file_path, 'w') as yaml_file:
        yaml_file.write( yaml.dump(data, default_flow_style=False))


def dns_wrapper(domain_set):

    ret_list = []
    #print(domain_set)
    try:

        # print(port_obj_arr)
        thread_map = {}
        pool = ThreadPool(processes=20)

        for domain in domain_set:
            # Add argument without domain first
            thread_map[domain] = pool.apply_async(socket.gethostbyname, (domain, ))

        # Close the pool
        pool.close()

        # Loop through thread function calls and update progress
        #print(thread_map)
        for domain_str in thread_map:

            ip_domain_map = {}

            # Add domain
            ip_domain_map['domain'] = domain_str
            thread_obj = thread_map[domain_str]

            try:
                ip_str = thread_obj.get()
            except socket.gaierror as e:
                continue
            except Exception as e:
                print(e)
                continue
                
            # print("IP: %s" % ip_str)
            if ip_str and len(ip_str) > 0:

                # Ignore any autogenerated DNS names
                ip_arr = ip_str.split(".")
                ip_dot = ip_arr[2]+"."+ip_arr[3]
                ip_dash = ip_arr[2]+"-"+ip_arr[3]
                if ip_dot in domain_str or ip_dash in domain_str:
                    continue

                ip_domain_map['ip'] = ip_str

                # Add to the list
                ret_list.append(ip_domain_map)
                print("[*] Adding IP %s for hostname %s" % (ip_str, domain_str))

    except subprocess.CalledProcessError as e:
        print("[*] called process error")
        pass
    except Exception as e:
        # Here we add some debugging help. If multiprocessing's
        # debugging is on, it will arrange to log the traceback
        print("[-] subfinder DNS thread exception.")
        print(traceback.format_exc())

    return ret_list


@inherits(SubfinderScope)
class SubfinderScan(luigi.Task):


    def requires(self):
        # Requires subfinderScope Task to be run prior
        return SubfinderScope(scan_input=self.scan_input)

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        # Get screenshot directory
        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "subfinder-outputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        # path to input file
        dns_outputs_file = dir_path + os.path.sep + "subfinder_outputs_" + scan_id
        return luigi.LocalTarget(dns_outputs_file)

    def run(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        # Read dns input files
        f = self.input().open()
        json_input = f.read()
        #print(json_input)
        f.close()

        # Ensure output folder exists
        meta_file_path = self.output().path
        dir_path = os.path.dirname(meta_file_path)
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        scan_output_file_path = dir_path + os.path.sep + "subfinder_results"

        # Write out meta data file
        output_fd = open(meta_file_path, 'w')
        ret_list = []
        
        #load input file
        if len(json_input) > 0:
            dns_scan_obj = json.loads(json_input)
            subfinder_domain_list = dns_scan_obj['input_path']
            api_keys = dns_scan_obj['api_keys']

            # Set the API keys
            update_config_file(api_keys)

            command = []
            if os.name != 'nt':
                command.append("sudo")

            command_arr = [
                "subfinder",
                "-json",
                "-dL",
                subfinder_domain_list,
                "-o",
                scan_output_file_path
            ]

            command.extend(command_arr)

            # Add optional arguments
            #command.extend(option_arr)

            # Execute subfinder
            scan_utils.process_wrapper(command)

            # Reset the API keys
            update_config_file({})

            domain_set = set()

            # Open output file
            if os.path.exists(scan_output_file_path):
                f = open(scan_output_file_path, 'r')
                scan_data = f.read()
                f.close()    

                #print(scan_data)
                # If there is output
                if len(scan_data) > 0:

                    json_blobs = scan_data.split("\n")
                    for blob in json_blobs:
                        blob_trimmed = blob.strip()
                        if len(blob_trimmed) > 0:
                            domain_entry = json.loads(blob)
                            domain_name = domain_entry['host']
                            domain_set.add(domain_name)


            # Add the domains from the wildcards
            f = open(subfinder_domain_list, 'r')
            sub_lines = f.readlines()
            f.close()   

            # Add the lines
            if len(sub_lines) > 0:
                for line in sub_lines:
                    line_str = line.strip()
                    if len(line_str) > 0:
                        domain_set.add(line_str)

            if len(domain_set) > 0:
                ret_list = dns_wrapper(domain_set)

        else:
            # Remove empty file
            os.remove(self.input().path)
        
        output_fd.write(json.dumps({'domain_list': ret_list}))
        output_fd.close()

        # Path to scan outputs log
        scan_utils.add_file_to_cleanup(scan_id, dir_path)


@inherits(SubfinderScan)
class SubfinderImport(luigi.Task):

    def requires(self):
        # Requires subfinderScan Task to be run prior
        return SubfinderScan(scan_input=self.scan_input)

    def output(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id

        cwd = os.getcwd()
        dir_path = cwd + os.path.sep + "subfinder-outputs-" + scan_id
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)
            os.chmod(dir_path, 0o777)

        out_file = dir_path + os.path.sep + "subfinder_import_complete"

        return luigi.LocalTarget(out_file)

    def run(self):

        scan_input_obj = self.scan_input
        scan_id = scan_input_obj.scan_id
        recon_manager = scan_input_obj.scan_thread.recon_manager

        subfinder_output_file = self.input().path
        f = open(subfinder_output_file, 'r')
        data = f.read()
        f.close()

        if len(data) > 0:
            domain_map = json.loads(data)
            #print(domain_map)

            if 'domain_list' in domain_map:
                domain_list = domain_map['domain_list']

                ip_map = {}
                #Convert from domain to ip map to ip to domain map
                for domain_entry in domain_list:

                    # Get IP for domain
                    domain_str = domain_entry['domain']
                    ip_str = domain_entry['ip']

                    if ip_str in ip_map:
                        domain_list = ip_map[ip_str]
                    else:
                        domain_list = set()
                        ip_map[ip_str] = domain_list

                    domain_list.add(domain_str)


                port_arr = []
                for ip_addr in ip_map:

                    domain_set = ip_map[ip_addr]
                    domains = list(domain_set)

                    ip_addr_int = int(netaddr.IPAddress(ip_addr))
                    #print(domains)
                    port_obj = {'ipv4_addr': ip_addr_int, 'domains': domains}

                    # Add to list
                    port_arr.append(port_obj)

                if len(port_arr) > 0:

                    # Import the ports to the manager
                    #ret_val = recon_manager.import_ports(port_arr)

                    tool_obj = scan_input_obj.current_tool
                    tool_id = tool_obj.id
                    scan_results = {'tool_id': tool_id, 'scan_id' : scan_id, 'port_list': port_arr}
                    #print(scan_results)
                    ret_val = recon_manager.import_ports_ext(scan_results)

                    # Write to output file
                    f = open(self.output().path, 'w')
                    f.write("complete")
                    f.close()