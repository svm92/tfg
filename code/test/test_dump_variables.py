#!/usr/bin/env python

import unittest
import sys
sys.path.insert(0, '..')
import webscan
import json
import os

variables = {
            "variable_1": "Value 1",
            "variable_2": "Value 2"
            }


class Test(unittest.TestCase):
    def test_dump_variables(self):
        webscan.book_json_location = "sample_report"
        webscan.dump_variables(variables)
        with open(webscan.book_json_location) as data_file:    
            data = json.load(data_file)
        self.assertEqual(data, {"variables": {"variable_2": "Value 2", "variable_1": "Value 1"}})
        os.remove("sample_report")

if __name__ == '__main__':
    unittest.main()

