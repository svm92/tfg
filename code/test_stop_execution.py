#!/usr/bin/env python

import unittest
import webscan


class Test(unittest.TestCase):
    def test_raise_exception(self):
        self.assertRaises(Exception)

if __name__ == '__main__':
    unittest.main()

