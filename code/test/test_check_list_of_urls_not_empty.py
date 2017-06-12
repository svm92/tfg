#!/usr/bin/env python

import unittest
import sys
sys.path.insert(0, '..')
import webscan


class Test(unittest.TestCase):
    def test_check_list_of_urls_not_empty(self):
        webscan.check_list_of_urls_not_empty(["url1", "url2"])
        self.assertRaises(SystemExit, webscan.check_list_of_urls_not_empty, [])

if __name__ == '__main__':
    unittest.main()

