#!/usr/bin/env python

import time

# Import OWASP ZAP modules
from zapv2 import ZAPv2

# Import OS modules to allow starting OWASP ZAP directly from python
import os
import subprocess

# Variable declaration
# Max number of children pages to scan (a higher number implies a slower but deeper scan)
max_children = 3 

# Starts OWASP ZAP
# The '-daemon' switch makes it start in headless mode (without a graphical interface)
# 'stdout=open(os.devnull,'w')' ensures there is no output in most operative systems
print 'Starting OWASP ZAP'
subprocess.Popen(['/home/samuel/Escritorio/ZAP_2.5.0/zap.sh','-daemon'],stdout=open(os.devnull,'w'))
time.sleep(5)

# Define the target URL
target = 'http://localhost/mutillidae'
#target = 'http://www.example.com'

# Start the ZAP API client (uses the default port 8080 and no API key)
zap = ZAPv2()

# Access the target URL
print 'Accessing target %s' % target
while True: # Will constantly try to connect until succesful (until the program opens)
    try:
        time.sleep(2)         # Try to connect every 2 seconds
        zap.urlopen(target)   # If unsuccesful, will throw an exception and retry
        break
    except:
         pass



# Starts the Spider process to fetch the site's pages
print 'Spidering target %s' % target
scanid = zap.spider.scan(target, max_children)
time.sleep(2)
# The process continues until zap.spider.status() reaches 100, updating the status every 2 seconds
while (int(zap.spider.status()) < 100):
    print 'Spider progress %: ' + zap.spider.status()
    time.sleep(2)

# The spidering process ends
print 'Spider completed'
time.sleep(5)

# Starts the active scan
print 'Scanning target %s' % target
scanid = zap.ascan.scan(target)
# The process continues until zap.ascan.status() reaches 100, updating the status every 5 seconds
while (int(zap.ascan.status(scanid)) < 100):
    print 'Scan progress %: ' + zap.ascan.status(scanid)
    time.sleep(5)

# The scan ends
print 'Scan completed'

# Report the results
print 'N of Alerts: ' + zap.core.number_of_alerts()
alerts = zap.core.alerts() # Saves the alerts as a list of dictionaries by default

# Output the alerts to a file
#f = open('/home/samuel/Escritorio/testreport','w')
#f.write(str(zap.core.alerts()))
#f.close()

#for i in range(len(alerts)):
#    print(alerts[i]["name"])


# Close OWASP ZAP
print 'Closing OWASP ZAP'
zap.core.shutdown()
