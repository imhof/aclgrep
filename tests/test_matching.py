#!/usr/bin/env python
# encoding: utf-8

import sys
import unittest

# import aclgrep code from one directory above
sys.path.append("..")
from aclgrep import ACLGrepper

class matching(unittest.TestCase):

    def setUp(self):
        # the parameters do not matter for the generic tests
        self.ag = ACLGrepper()

if __name__ == '__main__':
    unittest.main()
