#!/usr/bin/env python

import unittest
import sys
sys.path.insert(0, '..')
import webscan

sample_vulnerabilities = ["name1", "name2", "name3"]
sample_report = [{"url" : "url1", "name" : "name1"} ,{"url" : "url2", "name" : "name1"} ,{"url" : "url3", "name" : "name2"} ,{"url" : "url1", "name" : "name3"}, {"url" : "url1", "name" : "name1"}]

sample_result = [["url1", "url2"], ["url3"], ["url1"]]

class Test(unittest.TestCase):
    def test_get_urls(self):
        sample_urls = webscan.get_urls(sample_vulnerabilities, sample_report)
        for i in range(len(sample_urls)):
            self.assertCountEqual(sample_urls[i], sample_result[i])

if __name__ == '__main__':
    unittest.main()

