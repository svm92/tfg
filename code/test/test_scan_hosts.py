#!/usr/bin/env python

import unittest
from unittest.mock import patch
import sys
sys.path.insert(0, '..')
import webscan
import nmap

def mock_hosts():
    return ["127.0.0.1", "127.0.0.2", "127.0.0.3"]

def mock_getitem(host):
    return nmap.PortScannerHostDict

def mock_state_up():
    return "up"

def mock_state_down():
    return "down"

@patch("nmap.PortScanner.scan")
@patch("nmap.PortScanner.all_hosts", side_effect=mock_hosts)        
@patch("nmap.PortScanner.__getitem__", side_effect=mock_getitem) 
class Test(unittest.TestCase):
    @patch("nmap.PortScannerHostDict.state", side_effect=mock_state_up) 
    def test_scan_hosts(self, mock_scan, mock_hosts, mock_getitem, mock_state_up):
        self.assertEqual(webscan.scan_hosts("127.0.0.1"), ["127.0.0.1", "127.0.0.2", "127.0.0.3"])

    @patch("nmap.PortScannerHostDict.state", side_effect=mock_state_down) 
    def test_scan_hosts_down(self, mock_scan, mock_hosts, mock_getitem, mock_state_down):
        self.assertEqual(webscan.scan_hosts("127.0.0.1"), [])

if __name__ == '__main__':
    unittest.main()

