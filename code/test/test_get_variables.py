#!/usr/bin/env python

import unittest
import sys
sys.path.insert(0, '..')
import webscan

zap_version = "2.5.0"
n_of_vuln = 10
webscan.max_children_pages_to_scan = 3
webscan.target_url = "foo"
sample_report = [{"url" : "a", "name" : "b", "solution" : "c", "description" : "d", "risk" : "Low"}]


class Test(unittest.TestCase):
    def test_get_variables(self):
        self.assertEqual(webscan.get_variables(sample_report, zap_version, n_of_vuln), 
{'zap_version': '2.5.0', 'n_of_vulnerabilities': 10, 'max_children': 3, 'target_URL': 'foo', 'urls': ['a'], 'vulnerabilities': ['b'], 'solutions': ['c'], 'descriptions': ['d'], 'n_of_low_risks': 1, 'n_of_medium_risks': 0, 'n_of_high_risks': 0})

if __name__ == '__main__':
    unittest.main()

