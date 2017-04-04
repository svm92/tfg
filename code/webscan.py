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


def start_owasp():
    print("Opening OWASP ZAP")
    # The '-daemon' switch makes it start in headless mode (without a graphical interface)
    # 'stdout=open(os.devnull,'w')' ensures there is no output in most operative systems
    subprocess.Popen([owasp_location,"-daemon"],stdout=open(os.devnull,"w"))

def access_url(target_url):
    print("Accessing {}".format(target_url))
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

# The 'spidering' process fetches the site's pages
def spider_target(target_url, max_children_pages_to_scan):
    print("Spidering {}".format(target_url))
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
    print("Scanning {}".format(target_url))
    scanid = zap.ascan.scan(target_url)
    # The process continues until zap.ascan.status() reaches 100
    while (int(zap.ascan.status(scanid)) < 100):
        print("Scan progress: " + zap.ascan.status(scanid) + "%")
        time.sleep(5)

    # The scan ends
    print("Scan completed")

def save_results():
    alerts = zap.core.alerts() # Saves the alerts as a list of dictionaries by default
    return alerts

def close_owasp():
    print("Closing OWASP ZAP")
    zap.core.shutdown()

def generate_report(alerts):
    book_json_info = get_variables(alerts)
    dump_variables(book_json_info)
    os.chdir(os.path.dirname(book_json_location))
    os.system('gitbook pdf . scan_report.pdf')

def get_variables(alerts):
    vulnerabilities = get_list_without_duplicates("name", alerts)
    urls = get_list_without_duplicates("url", alerts)
    solutions = get_list_without_duplicates("solution", alerts)

    risks = get_list_with_duplicates("risk", alerts)
    n_of_low_risks = risks.count("Low")
    n_of_medium_risks = risks.count("Medium")
    n_of_high_risks = risks.count("High")

    # Specify the variables to be sent to the book.json file
    book_json_info = { "vulnerabilities" : vulnerabilities,
                     "n_of_low_risks" : n_of_low_risks,
                     "n_of_medium_risks" : n_of_medium_risks,
                     "n_of_high_risks" : n_of_high_risks,
                     "urls" : urls,
                     "solutions" : solutions,
                     "zap_version" : zap.core.version,
                     "max_children" : max_children_pages_to_scan,
                     "target_URL" : target_url,
                     "n_of_vulnerabilities" : zap.core.number_of_alerts()}
    return book_json_info

# Function to get data from the automated report and dump it into a list
def get_list_with_duplicates(tag, alerts):
    information = [] # Initialize the list
    for i in range(len(alerts)):
        # For every element [i] of the list, get the element that corresponds to the specified tag
        information.append(alerts[i][tag]) # Create a list from these elements
    return information

def get_list_without_duplicates(tag, alerts):
    info = get_list_with_duplicates(tag, alerts)
    info = set(info)    # Removes the duplicates, but disorders the list
    info = sorted(info) # Reorders the list
    return info

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


start_owasp()
zap = ZAPv2() # Start the ZAP API client (with default port 8080 and no API key)
access_url(target_url)
spider_target(target_url, max_children_pages_to_scan)
active_scan_on_target(target_url)
alerts = save_results()
close_owasp()
generate_report(alerts)

