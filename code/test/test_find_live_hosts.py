#!/usr/bin/env python

import unittest
from unittest.mock import patch
import sys
sys.path.insert(0, '..')
import webscan

def mock_scan(cidr):
    if cidr == "127.0.0.1/8":
        return ["127.0.0.1", "127.0.0.2"]
    if cidr == "10.0.2.15/24":
        return ["10.0.2.15"]

class Test(unittest.TestCase):
    @patch("webscan.scan_hosts", side_effect=mock_scan)
    def test_find_live_hosts(self, mock_scan):
        self.assertEqual(webscan.find_live_hosts(["127.0.0.1/8", "10.0.2.15/24"]), ["127.0.0.1", "127.0.0.2", "10.0.2.15"])

if __name__ == '__main__':
    unittest.main()

