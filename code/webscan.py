#!/usr/bin/env python

import time
import os
import subprocess

import json
import nmap
from zapv2 import ZAPv2

max_children_pages_to_scan = 1  # 0 for all
target_url = "http://127.0.0.1"#"http://localhost"
owasp_location = "/home/samuel/Escritorio/ZAP_2.5.0/zap.sh"
book_json_location = "/home/samuel/test-report-skeleton/book.json"

# This is the API key for ZAP, found under Tools -> Options -> API. The API key is optional and can be disabled, but it's not recommended since it prevents malicious sites from accessing the ZAP API
api_key = "3hf8lvqi3dqtau7dab20b292bq"

# Function to remove the scheme at the beginning of a URL (needed for nmap)
def remove_scheme(url):
    try:
        from urllib.parse import urlparse # Python 3 
    except ImportError:
        from urlparse import urlparse     # Python 2
    return urlparse(url).geturl().replace(urlparse(url).scheme + "://", "", 1)

# Function to add the "http://" at the beginning of a URL (needed for OWASP ZAP)
def add_http_to_url(url):
    if not url.startswith("http://"):
        return "http://" + url
    return url

def find_live_hosts(target_url):
    print("Finding live hosts")
    nm = nmap.PortScanner()
    target_url = remove_scheme(target_url) # Needed for nmap
    host_range = target_url + "/24"
    nm.scan(hosts=host_range, arguments="-sn") # The "-sn" switch is used to find live hosts
    live_hosts = []
    for host in nm.all_hosts():
        if (nm[host].state() == "up"):
            live_hosts.append(host)
    return live_hosts

def find_open_ports(list_of_targets):
    list_of_ports = []
    for i in range(len(list_of_targets)):
        list_of_ports.append( scan_ports(list_of_targets[i]) )
    return list_of_ports

def scan_ports(host):
    print("Scanning ports for " + host)
    nm = nmap.PortScanner()
    scan_results = nm.scan(host)
    scan_results = scan_results["scan"][host] # Extract the section of interest within the results
    ports_with_apps = []
    if "tcp" in scan_results: # If any open ports were found    
        for port in scan_results["tcp"]: # Get all ports with a "http" service or a "ssl" (https) service
            if (scan_results["tcp"][port]["name"] == "http" or scan_results["tcp"][port]["name"] == "ssl"):
                ports_with_apps.append(port)
    return ports_with_apps

class OWASP(object):
    def __enter__(self):
        print("Opening OWASP ZAP")
        # The '-daemon' switch makes it start in headless mode (without a graphical interface)
        # 'stdout=open(os.devnull,'w')' ensures there is no output in most operating systems
        self.pid = subprocess.Popen([owasp_location,"-daemon"], stdout=open(os.devnull,"w"))
        self.zap = ZAPv2(apikey=api_key) # Start the ZAP API client (with default port 8080)
        return self

    # Tries to close OWASP ZAP and then ends the script's execution
    def __exit__(self, type, value, traceback):
        print("Closing OWASP ZAP")
        self.zap.core.shutdown()

    def scan(self, list_of_targets, list_of_ports):
        for i in range(len(list_of_targets)):
            if list_of_ports[i]: # If any ports were found for that URL (non-empty list)
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
        print("Accessing " + target_url)
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
                    #print e.message; raise SystemExit("Couldn't connect")#raise e
                    raise e

    # The 'spidering' process fetches the site's pages
    def spider_target(self, target_url, max_children_pages_to_scan):
        print("Spidering "+ target_url)
        scanid = self.zap.spider.scan(target_url, max_children_pages_to_scan)
        time.sleep(2) # Time for the spider to start
        # The process continues until zap.spider.status() reaches 100
        while (int(self.zap.spider.status()) < 100):
            print("Spider progress: " + self.zap.spider.status() + "%")
            time.sleep(2)

        # The spidering process ends
        print("Spider completed")
        time.sleep(5) # Time for the passive scan to finish

    def active_scan(self, target_url):
        print("Scanning " + target_url)
        scanid = self.zap.ascan.scan(target_url)
        # The process continues until zap.ascan.status() reaches 100
        while (int(self.zap.ascan.status(scanid)) < 100):
            print("Scan progress: " + self.zap.ascan.status(scanid) + "%")
            time.sleep(5)

        # The scan ends
        print("Scan completed")

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
    book_json_vars = { "variables": vars }
    with open(book_json_location, "w") as outfile:
        json.dump(book_json_vars, outfile)

def create_pdf():
    os.chdir(os.path.dirname(book_json_location))
    os.system('gitbook pdf . scan_report.pdf')

if __name__ == "__main__":
    list_of_targets = find_live_hosts(target_url)
    print(list_of_targets)
    #list_of_targets = ["127.0.0.1"]
    #list_of_ports = [[80]]
    list_of_ports = find_open_ports(list_of_targets)
    print(list_of_ports)
    with OWASP() as owasp_instance:
        owasp_instance.scan(list_of_targets, list_of_ports)
        generate_report(owasp_instance.results(), owasp_instance.version())

