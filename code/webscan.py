#!/usr/bin/env python

import time
import os
import subprocess

import json
from zapv2 import ZAPv2

max_children_pages_to_scan = 3  # 0 for all
target_url = "http://localhost/mutillidae"
owasp_location = "/home/samuel/Escritorio/ZAP_2.5.0/zap.sh"
book_json_location = "/home/samuel/test-report-skeleton/book.json"

# This is the API key for ZAP, found under Tools -> Options -> API. The API key is optional and can be disabled, but it's not recommended since it prevents malicious sites from accessing the ZAP API
api_key = "3hf8lvqi3dqtau7dab20b292bq"

def get_name_servers(target_url):
    dig = subprocess.Popen(["dig", target_url, "ns", "+short"], stdout=subprocess.PIPE)
    name_servers = dig.stdout.read()    # Save the output from 'dig' as a string
    name_servers = name_servers.split() # Split the string into a list
    # Remove trailing dots
    for i in range(len(name_servers)):
        name_servers[i] = name_servers[i][:-1] # Take every element except for the last (the dot)
    name_servers.append(target_url) # Add the orignal URL to the list of targets    
    return name_servers

def start_owasp():
    print("Opening OWASP ZAP")
    # The '-daemon' switch makes it start in headless mode (without a graphical interface)
    # 'stdout=open(os.devnull,'w')' ensures there is no output in most operating systems
    subprocess.Popen([owasp_location,"-daemon"],stdout=open(os.devnull,"w"))

def access_url(target_url):
    print("Accessing " + target_url)
    timeout_var = 0
    while True: # Will constantly try to connect until succesful
        try:
            time.sleep(2)
            timeout_var += 1
            zap.urlopen(target_url)
            # If unsuccesful, will throw an exception and retry
            break
        except:
            if (timeout_var >= 30): # If it can't connect after 1 minute, stop the script
                stop_execution()

# Tries to close OWASP ZAP and then ends the script's execution
def stop_execution():
    try:
        close_owasp()
    finally:
        raise SystemExit("Couldn't connect")

def scan_with_zap(list_of_targets):
    for i in range(len(list_of_targets)):
        access_url(list_of_targets[i])
        spider_target(list_of_targets[i], max_children_pages_to_scan)
        active_scan_on_target(list_of_targets[i])

# The 'spidering' process fetches the site's pages
def spider_target(target_url, max_children_pages_to_scan):
    print("Spidering "+ target_url)
    scanid = zap.spider.scan(target_url, max_children_pages_to_scan)
    time.sleep(2) # Time for the spider to start
    # The process continues until zap.spider.status() reaches 100
    while (int(zap.spider.status()) < 100):
        print("Spider progress: " + zap.spider.status() + "%")
        time.sleep(2)

    # The spidering process ends
    print("Spider completed")
    time.sleep(5) # Time for the passive scan to finish
    
def active_scan_on_target(target_url):
    print("Scanning " + target_url)
    scanid = zap.ascan.scan(target_url)
    # The process continues until zap.ascan.status() reaches 100
    while (int(zap.ascan.status(scanid)) < 100):
        print("Scan progress: " + zap.ascan.status(scanid) + "%")
        time.sleep(5)

    # The scan ends
    print("Scan completed")

def save_results():
    return zap.core.alerts() # Saves the alerts as a list of dictionaries by default

def close_owasp():
    print("Closing OWASP ZAP")
    zap.core.shutdown()

def generate_report(alerts):
    book_json_info = get_variables(alerts, zap_version, n_of_alerts)
    dump_variables(book_json_info)
    create_pdf()

def get_variables(alerts, zap_version, n_of_alerts):
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
                     "n_of_vulnerabilities" : n_of_alerts}
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
    list_of_targets = get_name_servers(target_url)
    start_owasp()
    zap = ZAPv2(apikey=api_key) # Start the ZAP API client (with default port 8080)
    scan_with_zap(list_of_targets)    
    alerts = save_results()
    zap_version = zap.core.version
    n_of_alerts = zap.core.number_of_alerts()
    close_owasp()
    generate_report(alerts)

