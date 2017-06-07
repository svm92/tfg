#!/usr/bin/env python

import unittest
import sys
sys.path.insert(0, '..')
import webscan

class Test(unittest.TestCase):
    def test_remove_targets_without_ports(self):
        list_of_targets = ["127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5"]
        list_of_ports = [[80],[],[],[443],[]]
        list_of_targets, list_of_ports = webscan.remove_targets_without_ports(list_of_targets, list_of_ports)
        self.assertEqual(list_of_targets, ["127.0.0.1", "127.0.0.4"])
        self.assertEqual(list_of_ports, [[80], [443]])

if __name__ == '__main__':
    unittest.main()

