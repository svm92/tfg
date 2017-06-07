#!/usr/bin/env python

import unittest
from unittest.mock import patch
import sys
sys.path.insert(0, '..')
import webscan

def mock_interfaces():
    return ['loc', 'enp0s3']

def mock_cidr(x):
    if x == 'loc':
        return '127.0.0.1/8'
    if x == 'enp0s3':
        return '10.0.2.15/24'

class Test(unittest.TestCase):   
    @patch("netifaces.interfaces", side_effect=mock_interfaces)
    @patch("webscan.get_cidr", side_effect=mock_cidr)
    def test_find_all_cidrs(self, mock_ifaddresses, mock_cidr):
        self.assertEqual(webscan.find_all_cidrs(), ['127.0.0.1/8', '10.0.2.15/24'])

if __name__ == '__main__':
    unittest.main()

