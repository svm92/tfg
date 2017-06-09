#!/usr/bin/env python

import unittest
from unittest.mock import patch
import sys
sys.path.insert(0, '..')
import webscan

def mock_scan(host):
    if host == "127.0.0.1":
        return {'scan': {'127.0.0.1': {'tcp': {80: {'name': 'http'}, 81: {'name': 'http'}, 443: {'name': 'ssl'}, 3306: {'name': 'mysql'}}}}}
    if host == "127.0.0.2":
        return {'scan': {'127.0.0.2': {'tcp': {20: {'name': 'ftp'}}}}}
    if host == "127.0.0.3":
        return {'scan': {'127.0.0.3': {}}}

class Test(unittest.TestCase):
    @patch("nmap.PortScanner.scan", side_effect=mock_scan)
    def test_scan_ports(self, mock_scan):
        self.assertEqual(webscan.scan_ports("127.0.0.1"), ["http://127.0.0.1:80", "http://127.0.0.1:81", "https://127.0.0.1:443"])
        self.assertEqual(webscan.scan_ports("127.0.0.2"), [])
        self.assertEqual(webscan.scan_ports("127.0.0.3"), [])

if __name__ == '__main__':
    unittest.main()

