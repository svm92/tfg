#!/usr/bin/env python

import unittest
import webscan

sample_report = [{"risk" : "Low", "name" : "name1"} , {"risk" : "Low", "name" : "name2"} ,{"risk" : "High", "name" : "name3"}]

class Test(unittest.TestCase):
    def test_get_list_with_duplicates(self):
        self.assertItemsEqual(webscan.get_list_with_duplicates("risk", sample_report), ["Low", "Low", "High"])
        self.assertItemsEqual(webscan.get_list_with_duplicates("name", sample_report), ["name1", "name2", "name3"])

if __name__ == '__main__':
    unittest.main()

