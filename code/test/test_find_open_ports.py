#!/usr/bin/env python

import unittest
from unittest.mock import patch
import sys
sys.path.insert(0, '..')
import webscan


def return_some_ports(x):
    if x == "127.0.0.1":
        return ["http://127.0.0.1:80", "http://127.0.0.1:81", "https://127.0.0.1:443"]
    if x == "127.0.0.5":
        return ["http://127.0.0.5:90"]

class Test(unittest.TestCase):
    @patch("webscan.scan_ports", side_effect=return_some_ports)
    def test_find_open_ports(self, mock_function):
        self.assertEqual(webscan.find_open_ports(["127.0.0.1", "127.0.0.5"]), ["http://127.0.0.1:80", "http://127.0.0.1:81", "https://127.0.0.1:443", "http://127.0.0.5:90"])


if __name__ == '__main__':
    unittest.main()

