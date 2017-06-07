#!/usr/bin/env python

import unittest
import sys
sys.path.insert(0, '..')
import webscan
import os


class Test(unittest.TestCase):
    def test_initialize_log_handling(self):
        logger = webscan.initialize_log_handling()
        logger.debug("Test debug message")
        with open("webscan.log") as data_file:    
            data = data_file.read()
        self.assertTrue(data.endswith("[DEBUG] - Test debug message\n"))
        os.remove("webscan.log")

if __name__ == '__main__':
    unittest.main()

