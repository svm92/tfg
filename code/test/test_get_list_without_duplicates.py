#!/usr/bin/env python

import unittest
import sys
sys.path.insert(0, '..')
import webscan

sample_report = [{"risk" : "Low"} , {"risk" : "Low"}, {"risk" : "High"}]

class Test(unittest.TestCase):
    def test_get_list_without_duplicates(self):
        self.assertCountEqual(webscan.get_list_without_duplicates("risk", sample_report), ["Low", "High"])

if __name__ == '__main__':
    unittest.main()

