#!/usr/bin/env python

# Module for jinja2
#import jinja2

# (To be deleted)
# Scan results:
alerts = [{u'attack': u'', u'confidence': u'Medium', u'description': u'A cookie has been set without the HttpOnly flag, which means that the cookie can be accessed by JavaScript. If a malicious script can be run on this page then the cookie will be accessible and can be transmitted to another site. If this is a session cookie then session hijacking may be possible.', u'reference': u'http://www.owasp.org/index.php/HttpOnly', u'url': u'http://localhost/mutillidae/', u'solution': u'Ensure that the HttpOnly flag is set for all cookies.', u'param': u'PHPSESSID', u'evidence': u'Set-Cookie: PHPSESSID', u'pluginId': u'10010', u'other': u'', u'alert': u'Cookie No HttpOnly Flag', u'messageId': u'3', u'id': u'0', u'wascid': u'13', u'cweid': u'16', u'risk': u'Low', u'name': u'Cookie No HttpOnly Flag'}, {u'attack': u'', u'confidence': u'Medium', u'description': u'A cookie has been set without the HttpOnly flag, which means that the cookie can be accessed by JavaScript. If a malicious script can be run on this page then the cookie will be accessible and can be transmitted to another site. If this is a session cookie then session hijacking may be possible.', u'reference': u'http://www.owasp.org/index.php/HttpOnly', u'url': u'http://localhost/mutillidae/', u'solution': u'Ensure that the HttpOnly flag is set for all cookies.', u'param': u'showhints', u'evidence': u'Set-Cookie: showhints', u'pluginId': u'10010', u'other': u'', u'alert': u'Cookie No HttpOnly Flag', u'messageId': u'3', u'id': u'1', u'wascid': u'13', u'cweid': u'16', u'risk': u'Low', u'name': u'Cookie No HttpOnly Flag'}, {u'attack': u'', u'confidence': u'Medium', u'description': u"Web Browser XSS Protection is not enabled, or is disabled by the configuration of the 'X-XSS-Protection' HTTP response header on the web server", u'reference': u'https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet\nhttps://blog.veracode.com/2014/03/guidelines-for-setting-security-headers/', u'url': u'http://localhost/mutillidae/', u'solution': u"Ensure that the web browser's XSS filter is enabled, by setting the X-XSS-Protection HTTP response header to '1'.", u'param': u'X-XSS-Protection', u'evidence': u'', u'pluginId': u'10016', u'other': u"The X-XSS-Protection HTTP response header allows the web server to enable or disable the web browser's XSS protection mechanism. The following values would attempt to enable it: \nX-XSS-Protection: 1; mode=block\nX-XSS-Protection: 1; report=http://www.example.com/xss\nThe following values would disable it:\nX-XSS-Protection: 0\nThe X-XSS-Protection HTTP response header is currently supported on Internet Explorer, Chrome and Safari (WebKit).\nNote that this alert is only raised if the response body could potentially contain an XSS payload (with a text-based content type, with a non-zero length).", u'alert': u'Web Browser XSS Protection Not Enabled', u'messageId': u'3', u'id': u'2', u'wascid': u'14', u'cweid': u'933', u'risk': u'Low', u'name': u'Web Browser XSS Protection Not Enabled'}, {u'attack': u'', u'confidence': u'Medium', u'description': u"The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.", u'reference': u'http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx\nhttps://www.owasp.org/index.php/List_of_useful_HTTP_headers', u'url': u'http://localhost/mutillidae/', u'solution': u"Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.\nIf possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.", u'param': u'X-Content-Type-Options', u'evidence': u'', u'pluginId': u'10021', u'other': u'This issue still applies to error type pages (401, 403, 500, etc) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.\nAt "High" threshold this scanner will not alert on client or server error responses.', u'alert': u'X-Content-Type-Options Header Missing', u'messageId': u'3', u'id': u'3', u'wascid': u'15', u'cweid': u'16', u'risk': u'Low', u'name': u'X-Content-Type-Options Header Missing'}, {u'attack': u'', u'confidence': u'Medium', u'description': u"X-Frame-Options header is not included in the HTTP response to protect against 'ClickJacking' attacks.", u'reference': u'http://blogs.msdn.com/b/ieinternals/archive/2010/03/30/combating-clickjacking-with-x-frame-options.aspx', u'url': u'http://localhost/mutillidae/', u'solution': u"Most modern Web browsers support the X-Frame-Options HTTP header. Ensure it's set on all web pages returned by your site (if you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. ALLOW-FROM allows specific websites to frame the web page in supported web browsers).", u'param': u'X-Frame-Options', u'evidence': u'', u'pluginId': u'10020', u'other': u'', u'alert': u'X-Frame-Options Header Not Set', u'messageId': u'3', u'id': u'4', u'wascid': u'15', u'cweid': u'16', u'risk': u'Medium', u'name': u'X-Frame-Options Header Not Set'}, {u'attack': u'', u'confidence': u'Medium', u'description': u"Web Browser XSS Protection is not enabled, or is disabled by the configuration of the 'X-XSS-Protection' HTTP response header on the web server", u'reference': u'https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet\nhttps://blog.veracode.com/2014/03/guidelines-for-setting-security-headers/', u'url': u'http://localhost/robots.txt', u'solution': u"Ensure that the web browser's XSS filter is enabled, by setting the X-XSS-Protection HTTP response header to '1'.", u'param': u'X-XSS-Protection', u'evidence': u'', u'pluginId': u'10016', u'other': u"The X-XSS-Protection HTTP response header allows the web server to enable or disable the web browser's XSS protection mechanism. The following values would attempt to enable it: \nX-XSS-Protection: 1; mode=block\nX-XSS-Protection: 1; report=http://www.example.com/xss\nThe following values would disable it:\nX-XSS-Protection: 0\nThe X-XSS-Protection HTTP response header is currently supported on Internet Explorer, Chrome and Safari (WebKit).\nNote that this alert is only raised if the response body could potentially contain an XSS payload (with a text-based content type, with a non-zero length).", u'alert': u'Web Browser XSS Protection Not Enabled', u'messageId': u'8', u'id': u'5', u'wascid': u'14', u'cweid': u'933', u'risk': u'Low', u'name': u'Web Browser XSS Protection Not Enabled'}]


# In order to load the template from the system, the path must first be supplied
#templateLoader = jinja2.FileSystemLoader("/home/samuel/Escritorio")

# Create a template Environment object so that the templates can be parsed
#templateEnv = jinja2.Environment(loader=templateLoader)

# Read the template file and create a Template object
#template = templateEnv.get_template("reportskeleton")

# Function to get data from the automated report and dump it into a list
def get_data(target):
    information = [] # Initialize the list
    for i in range(len(alerts)):
        #print(alerts[i][target])
        # For every element [i] of the list, get the element that corresponds to the specified 'target' tag. It's necessary to convert it to string to remove the unicode tags
        information.append(str(alerts[i][target])) # Create a list from these elements
    return information

# Get data to later output it to the template
# get_data("name") returns every property with the tag "name" in alerts
# 'set' removes duplicates in a list. It also disorders them, so 'sorted' is used to solve this
vulnerabilities = sorted(set(get_data("name")))

urls = sorted(set(get_data("url")))

risks = get_data("risk")
n_of_low_risks = risks.count("Low")
n_of_medium_risks = risks.count("Medium")
n_of_high_risks = risks.count("High")



# description, solution

# Specify the variables to be sent to the template
templateVars = { "vulnerabilities" : vulnerabilities,
                 "n_of_low_risks" : n_of_low_risks,
                 "n_of_medium_risks" : n_of_medium_risks,
                 "n_of_high_risks" : n_of_high_risks,
                 "urls" : urls,
                 "n_of_vulnerabilities" : 3}

# Gitbook can read variables from a book.json file in the same directory
# First, the book.json file is opened (it is created if it doesn't exist)
f = open('/home/samuel/test-report-skeleton/book.json','w')

# The book.json file expects to find variables that follow this format:
#{
#    "variables": {
#        "variable_1": "Value 1",
#        "variable_2": "Value 2",
#        "variable_3": "Value 3"
#    }
#}
# The set of inner brackets corresponds to templateVars (although it must be turned into a string)
# The rest of the syntax can be achieved like this:
templateStr = "{\n    \"variables\": " + str(templateVars) + "\n}"
# json doesn't accept single quotes '' so they must be turned into double quotes ""
templateStr = templateStr.replace("\'", '\"')
f.write(templateStr)
f.close()


# Parse the template and save the output to a variable
#outputText = template.render(templateVars)


# Output the parsed template into a file (the file is created if it doesn't exist)
#f = open('/home/samuel/Escritorio/finalreport','w')
#f = open('helloworld','w')
#f.write(outputText)
#f.close()
