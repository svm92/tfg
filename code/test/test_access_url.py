#!/usr/bin/env python

import unittest
from unittest.mock import patch
import sys
sys.path.insert(0, '..')
import webscan
from zapv2 import ZAPv2

target_url = "127.0.0.1"

def mock_urlopen(x):
    if x == "positive_case":
        return
    if x == "negative_case":
        raise Exception

class Test(unittest.TestCase):
    @patch.object(ZAPv2, "urlopen", side_effect=mock_urlopen)
    @patch("time.sleep")
    def test_access_url(self, mock_urlopen, mock_time):
        self.owasp_instance = webscan.OWASP()
        self.owasp_instance.zap = ZAPv2()
        self.owasp_instance.access_url("positive_case")
        self.assertRaises(Exception, self.owasp_instance.access_url, "negative_case")

if __name__ == '__main__':
    unittest.main()

