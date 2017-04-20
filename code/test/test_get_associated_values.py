#!/usr/bin/env python

import unittest
import sys
sys.path.insert(0, '..')
import webscan

sample_vulnerabilities = ["name1", "name2", "name3"]
sample_report = [{"risk" : "Low", "name" : "name1"} ,{"risk" : "Low", "name" : "name1"} ,{"risk" : "Medium", "name" : "name2"} ,{"risk" : "High", "name" : "name3"}]

class Test(unittest.TestCase):
    def test_get_associated_values(self):
        self.assertEqual(webscan.get_associated_values(sample_vulnerabilities, "risk", sample_report), ["Low", "Medium", "High"])
        self.assertNotEqual(webscan.get_associated_values(sample_vulnerabilities, "risk", sample_report), ["Low", "High", "Medium"])

if __name__ == '__main__':
    unittest.main()

