#!/usr/bin/env python

import unittest
import sys
sys.path.insert(0, '..')
import webscan

class Test(unittest.TestCase):
    def test_add_http_to_url(self):
        self.assertEqual(webscan.add_http_to_url("www.example.com"), "http://www.example.com")
        self.assertEqual(webscan.add_http_to_url("http://www.example.com"), "http://www.example.com")

if __name__ == '__main__':
    unittest.main()

