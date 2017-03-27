#!/usr/bin/env python

import time
import os
import subprocess
import json

from zapv2 import ZAPv2

# Variable declaration
# Max number of children pages to scan, 0 for all (a higher number implies a slower but deeper scan)
max_children = 3

# Starts OWASP ZAP
# The '-daemon' switch makes it start in headless mode (without a graphical interface)
# 'stdout=open(os.devnull,'w')' ensures there is no output in most operative systems
print("Starting OWASP ZAP")
subprocess.Popen(['/home/samuel/Escritorio/ZAP_2.5.0/zap.sh','-daemon'],stdout=open(os.devnull,'w'))
time.sleep(5)

# Define the target URL
target = 'http://localhost/mutillidae'

# Start the ZAP API client (uses the default port 8080 and no API key)
zap = ZAPv2()

# Access the target URL
print("Accessing target {}".format(target))
while True: # Will constantly try to connect until succesful (until the program opens)
    try:
        time.sleep(2)         # Try to connect every 2 seconds
        zap.urlopen(target)   # If unsuccesful, will throw an exception and retry
        break
    except:
         pass



# Starts the Spider process to fetch the site's pages
print("Spidering target {}".format(target))
scanid = zap.spider.scan(target, max_children)
time.sleep(2)
# The process continues until zap.spider.status() reaches 100, updating the status every 2 seconds
while (int(zap.spider.status()) < 100):
    print("Spider progress: " + zap.spider.status() + "%")
    time.sleep(2)

# The spidering process ends
print("Spider completed")
time.sleep(5)

# Starts the active scan
print("Scanning target {}".format(target))
scanid = zap.ascan.scan(target)
# The process continues until zap.ascan.status() reaches 100, updating the status every 5 seconds
while (int(zap.ascan.status(scanid)) < 100):
    print("Scan progress: " + zap.ascan.status(scanid) + "%")
    time.sleep(5)

# The scan ends
print("Scan completed")

# Report the results
print("N of Alerts: " + zap.core.number_of_alerts())
alerts = zap.core.alerts() # Saves the alerts as a list of dictionaries by default

# Output the alerts to a file
f = open('/home/samuel/Escritorio/testreport','w')
f.write(str(zap.core.alerts()))
f.close()

# Close OWASP ZAP
print("Closing OWASP ZAP")
zap.core.shutdown()


print("Generating Report")


# Function to get data from the automated report and dump it into a list
def get_data(target):
    information = [] # Initialize the list
    for i in range(len(alerts)):
        # For every element [i] of the list, get the element that corresponds to the specified
        #'target' tag. It's necessary to convert it to string to remove the unicode tags
        information.append(str(alerts[i][target])) # Create a list from these elements
    return information

# Get data to later output it to the template
# get_data("name") returns every property with the tag "name" in alerts
# 'set' removes duplicates in a list. It also disorders them, so 'sorted' is used to solve this
vulnerabilities = sorted(set(get_data("name")))

urls = sorted(set(get_data("url")))

solutions = sorted(set(get_data("solution")))

risks = get_data("risk")
n_of_low_risks = risks.count("Low")
n_of_medium_risks = risks.count("Medium")
n_of_high_risks = risks.count("High")




# Specify the variables to be sent to the book.json file
templateVars = { "vulnerabilities" : vulnerabilities,
                 "n_of_low_risks" : n_of_low_risks,
                 "n_of_medium_risks" : n_of_medium_risks,
                 "n_of_high_risks" : n_of_high_risks,
                 "urls" : urls,
                 "solutions" : solutions,
                 "zap_version" : zap.core.version,
                 "max_children" : max_children,
                 "target_URL" : target,
                 "n_of_vulnerabilities" : zap.core.number_of_alerts()}

# The book.json file expects to find variables that follow this format:
#{
#    "variables": {
#        "variable_1": "Value 1",
#        "variable_2": "Value 2",
#        "variable_3": "Value 3"
#    }
#}
bookVars = { "variables": templateVars }

# Send the variables to the book.json file (it is created if it doesn't exist)
with open('/home/samuel/test-report-skeleton/book.json', 'w') as outfile:
    json.dump(bookVars, outfile)

