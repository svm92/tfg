#!/usr/bin/env python

import unittest
from unittest.mock import patch
import sys
sys.path.insert(0, '..')
import webscan
from zapv2 import ZAPv2

target_url = "127.0.0.1"
max_children_pages_to_scan = 5

def mock_status():
    return "100"

class Test(unittest.TestCase):   
    @patch("zapv2.spider.scan")
    @patch("zapv2.spider.status", side_effect=mock_status)
    @patch("time.sleep")
    def test_spider_target(self, mock_scan, mock_status, mock_time):
        self.owasp_instance = webscan.OWASP()
        self.owasp_instance.zap = ZAPv2()
        self.owasp_instance.spider_target(target_url, max_children_pages_to_scan)

if __name__ == '__main__':
    unittest.main()

