#!/usr/bin/env python

import unittest
import sys
sys.path.insert(0, '..')
import webscan

class Test(unittest.TestCase):   
    def test_get_full_url(self):
        self.assertEqual(webscan.get_full_url("http", "127.0.0.1", 80), "http://127.0.0.1/")
        self.assertEqual(webscan.get_full_url("http", "127.0.0.1", 81), "http://127.0.0.1:81/")
        self.assertEqual(webscan.get_full_url("https", "127.0.0.1", 443), "https://127.0.0.1/")
        self.assertEqual(webscan.get_full_url("https", "127.0.0.1", 81), "https://127.0.0.1:81/")

if __name__ == '__main__':
    unittest.main()

