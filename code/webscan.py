#!/usr/bin/env python

import time
import os
import subprocess
import logging

import netifaces
import netaddr
import socket

import json
import nmap
from zapv2 import ZAPv2

max_children_pages_to_scan = 1  # 0 for all
owasp_location = "/home/samuel/Escritorio/ZAP_2.5.0/zap.sh"
book_json_location = "/home/samuel/test-report-skeleton/book.json"

# This is the API key for ZAP, found under Tools -> Options -> API. The API key is optional and can be disabled, but it's not recommended since it prevents malicious sites from accessing the ZAP API
api_key = "3hf8lvqi3dqtau7dab20b292bq"

def add_log_handler(handler, logger, info_level, info_format):
    handler.setLevel(info_level)
    handler.setFormatter(logging.Formatter(info_format))
    logger.addHandler(handler)

def initialize_log_handling():
    logger = logging.getLogger("webscan_logger")
    logger.setLevel(logging.DEBUG)
    # Create console handler (info level)
    add_log_handler(logging.StreamHandler(), logger, logging.INFO, "%(message)s")
    # Create file handler (debug level)
    add_log_handler(logging.FileHandler("webscan.log","w"), logger, logging.DEBUG, "%(asctime)s : [%(levelname)s] - %(message)s")
    return logger

def find_all_cidrs(): 
    ifaces = netifaces.interfaces() # Get all interfaces
    logger.debug("Interfaces found: " + str(ifaces))
    cidr_list = []
    for i in ifaces:
        if i == "lo": continue; # Skip the localhost
        cidr_list.append(get_cidr(i))
    logger.info("List of CIDRs: " + str(cidr_list))
    return cidr_list

def get_cidr(interface):
    logger.debug("Finding CIDR for " + str(interface))
    address_list = netifaces.ifaddresses(interface)
    ip_info = address_list[socket.AF_INET][0]
    address = ip_info['addr']
    netmask = ip_info['netmask']
    cidr = netaddr.IPNetwork(address + "/" + netmask)
    logger.debug("CIDR found: " + str(cidr))
    return str(cidr)

# Function to add the "http://" at the beginning of a URL (needed for OWASP ZAP)
def add_http_to_url(url):
    if not url.startswith("http://"):
        return "http://" + url
    return url

def find_live_hosts(cidr_list):
    live_hosts = []
    for cidr in cidr_list:       
        live_hosts.extend( scan_hosts(cidr) )
    logger.info("List of live hosts: " + str(live_hosts))
    return live_hosts

def scan_hosts(cidr):
    logger.info("Finding live hosts for " + cidr)
    nm = nmap.PortScanner()
    nm.scan(hosts=cidr, arguments="-sn") # The "-sn" switch is used to find live hosts
    live_hosts = []
    logger.debug("Hosts found: " + str(nm.all_hosts()))
    for host in nm.all_hosts():
        if (nm[host].state() == "up"):
            live_hosts.append(host)
    logger.debug("Hosts up: " + str(live_hosts))
    return live_hosts

def find_open_ports(list_of_targets):
    list_of_ports = []
    for i in range(len(list_of_targets)):
        list_of_ports.append( scan_ports(list_of_targets[i]) )
    logger.info("List of ports with potential web applications: " + str(list_of_ports))
    return list_of_ports

def scan_ports(host):
    logger.info("Scanning ports for " + host)
    nm = nmap.PortScanner()
    scan_results = nm.scan(host)
    scan_results = scan_results["scan"][host] # Extract the section of interest within the results
    logger.debug("Port scan results for " + str(host) + ": " + str(scan_results))
    ports_with_apps = []
    if "tcp" in scan_results: # If any open ports were found    
        for port in scan_results["tcp"]: # Get all ports with a "http" service or a "ssl" (https) service
            if (scan_results["tcp"][port]["name"] == "http" or scan_results["tcp"][port]["name"] == "ssl" or scan_results["tcp"][port]["name"] == "ssl/http"):
                ports_with_apps.append(port)
    logger.debug("Ports with applications in " + str(host) + ": " + str(ports_with_apps))
    return ports_with_apps

def remove_targets_without_ports(list_of_targets, list_of_ports):
    clean_list_of_targets = []
    clean_list_of_ports = []
    for i in range(len(list_of_targets)):
        if list_of_ports[i]: # If any ports were found for that URL (non-empty list)
            clean_list_of_targets.append( list_of_targets[i] )
            clean_list_of_ports.append( list_of_ports[i] )
    return clean_list_of_targets, clean_list_of_ports

class OWASP(object):
    def __enter__(self):
        logger.info("Opening OWASP ZAP")
        # The '-daemon' switch makes it start in headless mode (without a graphical interface)
        # 'stdout=open(os.devnull,'w')' ensures there is no output in most operating systems
        self.pid = subprocess.Popen([owasp_location,"-daemon"], stdout=open(os.devnull,"w"))
        self.zap = ZAPv2(apikey=api_key) # Start the ZAP API client (with default port 8080)
        return self

    # Tries to close OWASP ZAP and then ends the script's execution
    def __exit__(self, type, value, traceback):
        logger.info("Closing OWASP ZAP")
        self.zap.core.shutdown()

    def scan(self, list_of_targets, list_of_ports):
        for i in range(len(list_of_targets)):
            for j in range(len(list_of_ports[i])):
                if (list_of_ports[i][j] == 80): #For any port other than 80, add :port to the URL
                    target_url = list_of_targets[i]
                else:
                    target_url = list_of_targets[i] + ":" + str(list_of_ports[i][j])
                target_url = add_http_to_url(target_url) # OWASP needs an explicit "http://" in the URL
                self.access_url(target_url)
                self.spider_target(target_url, max_children_pages_to_scan)
                self.active_scan(target_url)

    def access_url(self, target_url):
        logger.info("Accessing " + target_url)
        timeout_var = 0
        while True: # Will constantly try to connect until succesful
            try:
                time.sleep(2)
                timeout_var += 1
                self.zap.urlopen(target_url)
                # If unsuccesful, will throw an exception and retry
                break
            except Exception as e:
                if (timeout_var >= 30): # If it can't connect after 1 minute, stop the script
                    logger.warn("Couldn't connect to " + target_url)
                    raise e

    # The 'spidering' process fetches the site's pages
    def spider_target(self, target_url, max_children_pages_to_scan):
        logger.info("Spidering "+ target_url)
        scanid = self.zap.spider.scan(target_url, max_children_pages_to_scan)
        time.sleep(2) # Time for the spider to start
        # The process continues until zap.spider.status() reaches 100
        while (int(self.zap.spider.status()) < 100):
            logger.info("Spider progress: " + self.zap.spider.status() + "%")
            time.sleep(2)

        # The spidering process ends
        logger.info("Spider completed")
        time.sleep(5) # Time for the passive scan to finish

    def active_scan(self, target_url):
        logger.info("Scanning " + target_url)
        scanid = self.zap.ascan.scan(target_url)
        # The process continues until zap.ascan.status() reaches 100
        while (int(self.zap.ascan.status(scanid)) < 100):
            logger.info("Scan progress: " + self.zap.ascan.status(scanid) + "%")
            time.sleep(5)

        # The scan ends
        logger.info("Scan completed")

    def version(self):
        return self.zap.core.version

    def results(self):
        return self.zap.core.alerts() # Saves the alerts as a list of dictionaries by default





def generate_report(alerts, zap_version):
    book_json_info = get_variables(alerts, zap_version)
    dump_variables(book_json_info)
    create_pdf()

def get_variables(alerts, zap_version):
    vulnerabilities = get_list_without_duplicates("name", alerts)
    solutions = get_associated_values(vulnerabilities, "solution", alerts)
    descriptions = get_associated_values(vulnerabilities, "description", alerts)
    urls = get_urls(vulnerabilities, alerts)    

    risks = get_list_with_duplicates("risk", alerts)
    n_of_low_risks = risks.count("Low")
    n_of_medium_risks = risks.count("Medium")
    n_of_high_risks = risks.count("High")

    # Specify the variables to be sent to the book.json file
    book_json_info = { "vulnerabilities" : vulnerabilities,
                     "n_of_low_risks" : n_of_low_risks,
                     "n_of_medium_risks" : n_of_medium_risks,
                     "n_of_high_risks" : n_of_high_risks,
                     "solutions" : solutions,
                     "descriptions" : descriptions,
                     "zap_version" : zap_version,
                     "max_children" : max_children_pages_to_scan,
                     "target_URL" : list_of_targets,
                     "urls" : urls,
                     "n_of_vulnerabilities" : len(alerts)}
    logger.debug("Collecting variables:" + str(book_json_info))
    return book_json_info

# Function to get data from the automated report and dump it into a list
def get_list_with_duplicates(tag, alerts):
    return [ alert[tag] for alert in alerts ]

def get_list_without_duplicates(tag, alerts):
    return list(set(get_list_with_duplicates(tag, alerts)))

# Function to get data that follows the same order as 'vulnerabilities', for ease of use
def get_associated_values(vulnerabilities, tag, alerts):
    vulnerabilities_with_duplicates = get_list_with_duplicates("name", alerts)
    return [ alerts[vulnerabilities_with_duplicates.index(v)][tag] for v in vulnerabilities ]

# Function to get every affected url for each particular vulnerability
def get_urls(vulnerabilities, alerts):
    url_list = [[] for i in range(len(vulnerabilities))] # Initialize list of lists
    for i in range(len(vulnerabilities)):
        for j in range(len(alerts)):
            if alerts[j]["name"] == vulnerabilities[i]:
                url_list[i].append( alerts[j]["url"] ) # Get every url with that vulnerability
        url_list[i] = list(set(url_list[i])) # Remove repeated urls
    return url_list

def dump_variables(vars):
    # The book.json file expects to find variables that follow this format:
    #{
    #    "variables": {
    #        "variable_1": "Value 1",
    #        "variable_2": "Value 2",
    #        "variable_3": "Value 3"
    #    }
    #}
    logger.debug("Sending variables to book.json file")
    book_json_vars = { "variables": vars }
    with open(book_json_location, "w") as outfile:
        json.dump(book_json_vars, outfile)

def create_pdf():
    logger.debug("Creating pdf file")
    os.chdir(os.path.dirname(book_json_location))
    os.system('gitbook pdf . scan_report.pdf')


# Empty logger (no logging) when called from outside, such as from a test
if __name__ != "__main__":
    logger = logging.getLogger()

if __name__ == "__main__":
    logger = initialize_log_handling()
    cidr_list = find_all_cidrs()
    list_of_targets = find_live_hosts(cidr_list)
    list_of_ports = find_open_ports(list_of_targets)
    list_of_targets, list_of_ports = remove_targets_without_ports(list_of_targets, list_of_ports)
    with OWASP() as owasp_instance:
        owasp_instance.scan(list_of_targets, list_of_ports)
        generate_report(owasp_instance.results(), owasp_instance.version())

