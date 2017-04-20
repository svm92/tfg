#!/usr/bin/env python

import unittest
import sys
sys.path.insert(0, '..')
import webscan
import os

class Test(unittest.TestCase):
    def test_path_exists(self):
        self.assertTrue(webscan.os.path.exists(webscan.book_json_location))

if __name__ == '__main__':
    unittest.main()

