#!/usr/bin/env python

import unittest
from unittest.mock import patch
import sys
sys.path.insert(0, '..')
import webscan
from zapv2 import ZAPv2

target_url = "127.0.0.1"

def mock_status(x):
    return "100"

class Test(unittest.TestCase):   
    @patch("zapv2.ascan.scan")
    @patch("zapv2.ascan.status", side_effect=mock_status)
    @patch("time.sleep")
    def test_active_scan(self, mock_scan, mock_status, mock_time):
        self.owasp_instance = webscan.OWASP()
        self.owasp_instance.zap = ZAPv2()
        self.owasp_instance.active_scan(target_url)

if __name__ == '__main__':
    unittest.main()

