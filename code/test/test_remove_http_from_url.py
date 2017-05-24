#!/usr/bin/env python

import unittest
import sys
sys.path.insert(0, '..')
import webscan

class Test(unittest.TestCase):
    def test_remove_http_from_url(self):
        self.assertEqual(webscan.remove_http_from_url("http://www.example.com"), "www.example.com")
        self.assertEqual(webscan.remove_http_from_url("www.example.com"), "www.example.com")

if __name__ == '__main__':
    unittest.main()

