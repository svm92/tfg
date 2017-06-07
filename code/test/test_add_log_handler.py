#!/usr/bin/env python

import unittest
import sys
sys.path.insert(0, '..')
import webscan
import logging

test_logger = logging.getLogger("test_logger")
test_logger.setLevel(logging.DEBUG)

class Test(unittest.TestCase):
    def test_add_log_handler(self):
        webscan.add_log_handler(logging.StreamHandler(), test_logger, logging.INFO, "")
        self.assertTrue(str(test_logger.handlers).startswith("[<logging.StreamHandler object at"))

if __name__ == '__main__':
    unittest.main()

