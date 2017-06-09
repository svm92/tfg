#!/usr/bin/env python

import unittest
import sys
sys.path.insert(0, '..')
import webscan

class Test(unittest.TestCase):   
    def test_find_scheme(self):
        self.assertEqual(webscan.find_scheme("http"), "http://")
        self.assertEqual(webscan.find_scheme("ssl"), "https://")
        self.assertEqual(webscan.find_scheme("ssl/http"), "https://")

if __name__ == '__main__':
    unittest.main()

