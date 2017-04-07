#!/usr/bin/env python

import unittest
import webscan
import json

class Test(unittest.TestCase):
    def test_dump_variables(self):
        webscan.dump_variables({
            "variable_1": "Value 1",
            "variable_2": "Value 2"
        })
        with open(webscan.book_json_location) as data_file:    
            data = json.load(data_file)
        self.assertEqual(data, {"variables": {"variable_2": "Value 2", "variable_1": "Value 1"}})

if __name__ == '__main__':
    unittest.main()

