import json
import os
import shodan
import netaddr
import luigi
import time
import ipaddress
import hashlib
import binascii
import logging

from luigi.util import inherits
from waluigi import scan_utils
from waluigi import data_model
from datetime import datetime
from urllib.parse import urlsplit, urlunsplit


class Shodan(data_model.WaluigiTool):

    def __init__(self):
        self.name = 'shodan'
        self.description = "Shodan is a search engine for Internet-connected devices"
        self.project_url = 'https://www.shodan.io/'
        self.collector_type = data_model.CollectorType.PASSIVE.value
        self.scan_order = 3
        self.args = ""
        self.import_func = Shodan.import_shodan

    @staticmethod
    def import_shodan(scan_input):
        luigi_run_result = luigi.build([ImportShodanOutput(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


class ShodanScope(luigi.ExternalTask):

    scan_input = luigi.Parameter()

    def output(self):

        scheduled_scan_obj = self.scan_input
        scan_id = scheduled_scan_obj.id

        # Init directory
        tool_name = scheduled_scan_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'inputs', scan_id)

        # path to each input file
        shodan_ip_file = dir_path + os.path.sep + "shodan_ips_" + scan_id
        if os.path.isfile(shodan_ip_file):
            return luigi.LocalTarget(shodan_ip_file)

        scope_obj = scheduled_scan_obj.scan_data
        target_list = []
        subnet_map = scope_obj.subnet_map
        for subnet_id in subnet_map:
            subnet_obj = subnet_map[subnet_id]
            subnet_str = "%s/%s" % (subnet_obj.subnet, subnet_obj.mask)
            target_list.append(subnet_str)

        host_list = scope_obj.get_hosts(
            [data_model.RecordTag.SCOPE.value, data_model.RecordTag.LOCAL.value])

        for host_obj in host_list:
            host_str = "%s/32" % (host_obj.ipv4_addr)
            target_list.append(host_str)

        logging.getLogger(__name__).debug("[+] Retrieved %d subnets from database" %
                                          len(target_list))
        imput_data = {'host_list': target_list}
        json_data = json.dumps(imput_data)

        with open(shodan_ip_file, 'w') as shodan_fd:
            shodan_fd.write(json_data)

        return luigi.LocalTarget(shodan_ip_file)


def shodan_dns_query(api, domain):

    info = None
    while True:
        try:
            info = api.dns.domain_info(domain, history=False, type="A")
            break
        except shodan.exception.APIError as e:
            err_msg = str(e).lower()

            if "limit reached" in err_msg:
                time.sleep(1)
                continue
            if "invalid api key" in err_msg:
                raise e
            if "no information" not in err_msg:
                logging.getLogger(__name__).error(
                    "Shodan API Error DNS: %s" % err_msg)
            break

    # Grab the host information for any IP records that were returned
    results = []
    if info:
        ip_arr = [record['value']
                  for record in info['data'] if record['type'] in ['A', 'AAAA']]
        ip_set = set(ip_arr)
        results = list(ip_set)

    return results


def shodan_host_query(api, ip):

    # logging.getLogger(__name__).error("Shodan Host Query: %s" % ip)
    service_list = []
    while True:
        try:
            results = api.host(str(ip))
            if 'data' in results:
                service_list = results['data']
            break
        except shodan.exception.APIError as e:
            err_msg = str(e).lower()
            if "limit reached" in err_msg:
                time.sleep(1)
                continue
            if "invalid api key" in err_msg:
                raise e
            if "no information" not in err_msg:
                logging.getLogger(__name__).error(
                    "Shodan API Error Host: %s" % err_msg)
            break

    return service_list


def shodan_subnet_query(api, subnet, cidr):

    # Query the subnet
    query = "net:%s/%s" % (str(subnet), str(cidr))

    # Loop through the matches and print each IP
    service_list = []
    while True:
        try:
            for service in api.search_cursor(query):
                service_list.append(service)
            break
        except shodan.exception.APIError as e:
            err_msg = str(e).lower()

            if "limit reached" in err_msg:
                time.sleep(1)
                continue
            if "invalid api key" in err_msg:
                raise e
            if "no information" not in err_msg:
                logging.getLogger(__name__).error(
                    "[-] Shodan API Error Subnet: %s" % err_msg)
            break

    return service_list


def shodan_wrapper(shodan_key, ip=None, cidr=None, domain=None):

    results = []
    # Setup the api
    api = shodan.Shodan(shodan_key)
    if ip and cidr:
        if cidr > 28:
            subnet = netaddr.IPNetwork(str(ip)+"/"+str(cidr))
            for ip in subnet.iter_hosts():
                results.extend(shodan_host_query(api, ip))
        else:
            results = shodan_subnet_query(api, ip, cidr)
    elif domain:
        results = shodan_dns_query(api, domain)

    return results


def reduce_subnets(ip_subnets):

    # Get results for the whole class C
    ret_list = []
    i = 24

    subnet_list = []
    for subnet in ip_subnets:
        # Add class C networks for all IPs
        net_inst = netaddr.IPNetwork(subnet.strip())

        # Skip private IPs
        ip_network = ipaddress.ip_network(subnet.strip())
        if ip_network.is_private:
            continue

        net_ip = str(net_inst.network)

        if net_inst.prefixlen < i:
            network = netaddr.IPNetwork(net_ip + "/%d" % i)
            c_network = network.cidr
            subnet_list.append(c_network)
        else:
            subnet_list.append(net_inst)

    # Merge subnets
    ret_list = netaddr.cidr_merge(subnet_list)

    return ret_list


@inherits(ShodanScope)
class ShodanScan(luigi.Task):

    def requires(self):
        # Requires the target scope
        return ShodanScope(scan_input=self.scan_input)

    def output(self):

        scheduled_scan_obj = self.scan_input
        scan_id = scheduled_scan_obj.id

        # Init directory
        tool_name = scheduled_scan_obj.current_tool.name
        dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)
        out_file = dir_path + os.path.sep + "shodan_out_" + scan_id

        return luigi.LocalTarget(out_file)

    def run(self):

        scheduled_scan_obj = self.scan_input

        # Read shodan input files
        shodan_input_file = self.input()
        input_data = None
        with shodan_input_file.open() as file_fd:
            input_data = json.loads(file_fd.read())

        # Write the output
        shodan_key = scheduled_scan_obj.current_tool.api_key
        if shodan_key and len(shodan_key) > 0:

            output_arr = []
            # Do a test lookup to make sure our key is good and we have connectivity
            result = shodan_wrapper(shodan_key, '8.8.8.8', 32)
            if result is not None:

                # futures = []
                # domain_set = set()
                # domains = input_data['domain_list']
                # for domain in domains:

                #     # Ensure no duplicates
                #     if domain not in domain_set:
                #         futures.append(scan_utils.executor.submit(
                #             shodan_wrapper, shodan_key=shodan_key, domain=domain))
                #         domain_set.add(domain)

                # dns_ip_arr = set()
                # for future in futures:
                #     result = future.result()
                #     dns_ip_arr.update(result)

                ip_subnets = input_data['host_list']

                # # Add the DNS IPs to the list
                # ip_subnets.extend(dns_ip_arr)

                # Attempt to consolidate subnets to reduce the number of shodan calls
                logging.getLogger(__name__).debug(
                    "Consolidating subnets queried by Shodan")

                if len(ip_subnets) > 50:
                    ip_subnets = reduce_subnets(ip_subnets)

                # Get the shodan key
                # logging.getLogger(__name__).debug("Retrieving Shodan data")

                futures = []
                for subnet in ip_subnets:

                    # Get the subnet
                    subnet = str(subnet)
                    subnet_arr = subnet.split("/")
                    ip = subnet_arr[0].strip()

                    cidr = 32
                    if len(subnet_arr) > 1:
                        cidr = int(subnet_arr[1])

                    # Skip private IPs
                    ip_network = ipaddress.ip_network(str(ip)+"/"+str(cidr))
                    if ip_network.is_private:
                        continue

                    futures.append(scan_utils.executor.submit(
                        shodan_wrapper, shodan_key=shodan_key, ip=ip, cidr=cidr))

                # Register futures with scan job
                scan_proc_inst = data_model.ToolExecutor(futures)
                scheduled_scan_obj.register_tool_executor(
                    scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

                # Wait for the tasks to complete and retrieve results
                for future in futures:
                    result = future.result()
                    output_arr.extend(result)

            # Open output file and write json of output
            outfile = self.output().path
            output_data = {"data": output_arr}
            with open(outfile, 'w') as f:
                f.write(json.dumps(output_data))

        else:
            logging.getLogger(__name__).error("No shodan API key provided.")
            raise Exception("No shodan API key provided")


@inherits(ShodanScan)
class ImportShodanOutput(data_model.ImportToolXOutput):

    def requires(self):
        return ShodanScan(scan_input=self.scan_input)

    def run(self):

        scheduled_scan_obj = self.scan_input
        tool_instance_id = scheduled_scan_obj.current_tool_instance_id

        shodan_output_file = self.input().path
        with open(shodan_output_file, 'r') as file_fd:
            data = file_fd.read()

        ret_arr = []
        path_hash_map = {}
        hash_alg = hashlib.sha1

        if len(data) > 0:
            # Import the shodan data
            json_data = json.loads(data)
            if json_data and len(json_data) > 0:

                scan_data = json_data['data']
                for service in scan_data:

                    host_id = None
                    port_id = None
                    ip_int = service['ip']
                    if host_id is None:
                        ip_object = netaddr.IPAddress(ip_int)

                        host_obj = data_model.Host(id=host_id)
                        host_obj.collection_tool_instance_id = tool_instance_id
                        if ip_object.version == 4:
                            host_obj.ipv4_addr = str(ip_object)
                        elif ip_object.version == 6:
                            host_obj.ipv6_addr = str(ip_object)
                        host_id = host_obj.id

                        # Add host
                        ret_arr.append(host_obj)

                    # See if a port exists for this service
                    port = service['port']
                    port_obj = data_model.Port(
                        parent_id=host_id)
                    port_obj.collection_tool_instance_id = tool_instance_id
                    port_obj.proto = 0
                    port_obj.port = port
                    port_id = port_obj.id

                    # Add port
                    ret_arr.append(port_obj)

                    # org_str = service['org']
                    # timestamp = service['timestamp']
                    # last_updated = int(
                    #    datetime.fromisoformat(timestamp).timestamp())

                    # Non HTTP SSL ports
                    if 'ssl' in service:
                        port_obj.secure = True

                        ssl = service['ssl']
                        if 'cert' in ssl:
                            cert = ssl['cert']
                            if 'subject' in cert:
                                subject = cert['subject']
                                if 'CN' in subject:
                                    domain_str = subject['CN'].lower()

                                    # Get or create a domain object
                                    domain_obj = data_model.Domain(
                                        parent_id=host_id)
                                    domain_obj.collection_tool_instance_id = tool_instance_id
                                    domain_obj.name = domain_str

                                    # Add domain
                                    ret_arr.append(domain_obj)

                    # Get http data
                    if 'http' in service:
                        http_dict = service['http']

                        endpoint_domain_id = None
                        if 'status' in http_dict:
                            status_code = http_dict['status']

                        if 'title' in http_dict:
                            title = http_dict['title']

                        if 'server' in http_dict:
                            server_str = http_dict['server']
                            if server_str:
                                server = server_str.strip().lower()
                                if len(server) > 0:
                                    if " " in server:
                                        server_tech = server.split(" ")[0]
                                    else:
                                        server_tech = server

                                    server_version = None
                                    if "/" in server_tech:
                                        server_tech_arr = server_tech.split(
                                            "/")
                                        server_tech = server_tech_arr[0]
                                        temp_val = server_tech_arr[-1].strip()
                                        if len(temp_val) > 0:
                                            server_version = temp_val

                                        component_obj = data_model.WebComponent(
                                            parent_id=port_id)
                                        component_obj.collection_tool_instance_id = tool_instance_id
                                        component_obj.name = server_tech

                                        # Add the version
                                        if server_version:
                                            component_obj.version = server_version

                                        ret_arr.append(component_obj)

                        favicon_hash = None
                        tmp_fav_hash = None
                        if 'favicon' in http_dict:
                            favicon_dict = http_dict['favicon']
                            tmp_fav_hash = favicon_dict['hash']
                            # favicon_url = favicon_dict['location']

                        if 'components' in http_dict:
                            components_dict = http_dict['components']
                            for component_name in components_dict:

                                components_dict_obj = components_dict[component_name]
                                # Convert to lower to avoid upper/lower issues
                                component_name = component_name.lower()

                                component_obj = data_model.WebComponent(
                                    parent_id=port_id)
                                component_obj.collection_tool_instance_id = tool_instance_id
                                component_obj.name = component_name

                                if 'versions' in components_dict_obj:
                                    version_arr = components_dict_obj['versions']
                                    if len(version_arr) > 0:
                                        component_obj.version = version_arr[0]

                                ret_arr.append(component_obj)

                        if 'ssl' in service:
                            port_obj.secure = True

                            ssl = service['ssl']
                            if 'cert' in ssl:
                                cert = ssl['cert']

                                # Create a certificate object
                                cert_obj = data_model.Certificate(
                                    parent_id=port_obj.id)
                                cert_obj.collection_tool_instance_id = tool_instance_id
                                if 'issued' in cert:
                                    issued = cert['issued']
                                    # Parse the time string into a datetime object in UTC
                                    dt = datetime.strptime(
                                        issued, '%Y%m%d%H%M%SZ')
                                    cert_obj.issued = int(
                                        time.mktime(dt.timetuple()))

                                if 'expires' in cert:
                                    expires = cert['expires']
                                    dt = datetime.strptime(
                                        expires,  '%Y%m%d%H%M%SZ')
                                    cert_obj.expires = int(
                                        time.mktime(dt.timetuple()))

                                if 'fingerprint' in cert:
                                    cert_hash_map = cert['fingerprint']
                                    if 'sha1' in cert_hash_map:
                                        sha_cert_hash = cert_hash_map['sha1']
                                        cert_obj.fingerprint_hash = sha_cert_hash

                                if 'subject' in cert:
                                    subject = cert['subject']
                                    if 'CN' in subject:
                                        domain_str = subject['CN'].lower()

                                        domain_obj = cert_obj.add_domain(
                                            host_id, domain_str, tool_instance_id)
                                        if domain_obj:
                                            ret_arr.append(domain_obj)

                                            endpoint_domain_id = domain_obj.id

                                 # Add the cert object
                                ret_arr.append(cert_obj)

                        hostname_arr = service['hostnames']
                        for domain_name in hostname_arr:
                            # Convert the domain to a lower since case doesn't matter
                            if len(domain_name) > 0:
                                domain_name = domain_name.lower()

                                # Get or create a domain object
                                domain_obj = data_model.Domain(
                                    parent_id=host_id)
                                domain_obj.collection_tool_instance_id = tool_instance_id
                                domain_obj.name = domain_name

                                # Add domain
                                ret_arr.append(domain_obj)

                        # Path may be "location"
                        if 'location' in http_dict:
                            path_location = http_dict['location']
                            if path_location and len(path_location) > 0:
                                split_url = urlsplit(path_location)

                                # Remove the query part
                                trimmed_url = split_url._replace(query='')

                                # Reconstruct the URL without the query part
                                trimmed_path = urlunsplit(trimmed_url)
                                if tmp_fav_hash and trimmed_path == "/":
                                    favicon_hash = tmp_fav_hash

                                hashobj = hash_alg()
                                hashobj.update(trimmed_path.encode())
                                path_hash = hashobj.digest()
                                hex_str = binascii.hexlify(path_hash).decode()
                                web_path_hash = hex_str

                                if web_path_hash in path_hash_map:
                                    path_obj = path_hash_map[web_path_hash]
                                else:
                                    path_obj = data_model.ListItem()
                                    path_obj.collection_tool_instance_id = tool_instance_id
                                    path_obj.web_path = trimmed_path
                                    path_obj.web_path_hash = web_path_hash

                                    # Add to map and the object list
                                    path_hash_map[web_path_hash] = path_obj
                                    ret_arr.append(path_obj)

                                web_path_id = path_obj.id

                        # Add http endpoint
                        http_endpoint_obj = data_model.HttpEndpoint(
                            parent_id=port_obj.id)
                        http_endpoint_obj.collection_tool_instance_id = tool_instance_id
                        http_endpoint_obj.web_path_id = web_path_id

                        # Add the endpoint
                        ret_arr.append(http_endpoint_obj)

                        http_endpoint_data_obj = data_model.HttpEndpointData(
                            parent_id=http_endpoint_obj.id)
                        http_endpoint_data_obj.collection_tool_instance_id = tool_instance_id
                        http_endpoint_data_obj.domain_id = endpoint_domain_id
                        http_endpoint_data_obj.title = title
                        http_endpoint_data_obj.status = status_code
                        http_endpoint_data_obj.fav_icon_hash = favicon_hash

                        # Add the endpoint
                        ret_arr.append(http_endpoint_data_obj)

        # Import, Update, & Save
        scheduled_scan_obj = self.scan_input
        self.import_results(scheduled_scan_obj, ret_arr)
