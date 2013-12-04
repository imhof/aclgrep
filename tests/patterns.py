#!/usr/bin/env python
# encoding: utf-8

import sys
import unittest

# import aclgrep code from one directory above
sys.path.append("..")
from aclgrep import ip_and_mask_to_pair, ip_and_cidr_to_pair, ip_to_bits, ip_in_net

class patterns(unittest.TestCase):
    def setUp(self):
        pass

    def testIpToBits(self):
        # go over range
        for x in range(0,256):
            ip = ("%d.%d.%d.%d" % (x,x,x,x))
            value = x * 0x1000000 + x * 0x10000 + x * 0x100 + x
            self.assertEqual(value, ip_to_bits(ip))

        # corner cases
        self.assertRaises(ValueError, ip_to_bits, "256.0.0.0")
        self.assertRaises(ValueError, ip_to_bits, "a")
        self.assertRaises(ValueError, ip_to_bits, "")

    def testIpMaskPair(self):
        # check values
        self.assertEqual((0x0a000000, 0xff000000), ip_and_mask_to_pair("10.0.0.0 255.0.0.0"))
        self.assertEqual((0xc0a80200, 0xfffffc00), ip_and_mask_to_pair("192.168.2.0 255.255.252.0"))
        # separator should not matter
        self.assertEqual(ip_and_mask_to_pair("192.168.2.0 255.255.255.0"), ip_and_mask_to_pair("192.168.2.0/255.255.255.0"))
        # equivalent subnet mask and wildcard mask
        self.assertEqual(ip_and_mask_to_pair("192.168.2.0 255.255.255.0"), ip_and_mask_to_pair("192.168.2.0 0.0.0.255"))

        # full bits -> interpret as host TODO: is this correct?
        self.assertEqual((0x0a020304, 0xffffffff), ip_and_mask_to_pair("10.2.3.4 255.255.255.255"))
        # no bits -> host
        self.assertEqual((0x0a010101, 0xffffffff), ip_and_mask_to_pair("10.1.1.1/0.0.0.0"))

    def testIpCidrPair(self):
        # check values
        self.assertEqual((0x0a000000, 0xff000000), ip_and_cidr_to_pair("10.0.0.0/8"))
        self.assertEqual((0xc0a80200, 0xfffffc00), ip_and_cidr_to_pair("192.168.2.0/22"))

    def testIpInNet(self):
        self.assertTrue(ip_in_net(0x0a010101, (0x0a000000, 0xff000000)))
        self.assertFalse(ip_in_net(0x0a010101, (0x0a000000, 0xffffff00)))

if __name__ == '__main__':
    unittest.main()
