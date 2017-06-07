#!/usr/bin/env python

import unittest
from unittest.mock import patch
import sys
sys.path.insert(0, '..')
import webscan

def mock_ifaddresses(x):
    return {17: [{'addr': '00:00:00:00:00:00', 'peer': '00:00:00:00:00:00'}], 2: [{'netmask': '255.0.0.0', 'addr': '127.0.0.1', 'peer': '127.0.0.1'}], 10: [{'netmask': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128', 'addr': '::1'}]}

class Test(unittest.TestCase):   
    @patch("netifaces.ifaddresses", side_effect=mock_ifaddresses)
    def test_get_cidr(self, mock_ifaddresses):
        self.assertEqual(webscan.get_cidr("lo"), "127.0.0.1/8")

if __name__ == '__main__':
    unittest.main()

