#!/usr/bin/env python

import unittest
import sys
sys.path.insert(0, '..')
import webscan

zap_version = "2.5.0"
n_of_vuln = 10
webscan.max_children_pages_to_scan = 3
webscan.list_of_targets = "foo"
sample_report = [{"name" : "a", "solution" : "b", "description" : "c", "risk" : "Low", "url" : "D"}]


class Test(unittest.TestCase):
    def test_get_variables(self):
        self.assertEqual(webscan.get_variables(sample_report, zap_version, n_of_vuln), 
{'zap_version': '2.5.0', 'n_of_vulnerabilities': 10, 'max_children': 3, 'target_URL': 'foo', 'vulnerabilities': ['a'], 'solutions': ['b'], 'descriptions': ['c'], 'urls': [['D']], 'n_of_low_risks': 1, 'n_of_medium_risks': 0, 'n_of_high_risks': 0})

if __name__ == '__main__':
    unittest.main()

