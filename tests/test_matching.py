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
        self.onlySIP = ACLGrepper("192.168.2.12")
        self.onlyDIP = ACLGrepper(None, None, "224.1.156.12")

    def testMatchSIP(self):
        self.assertTrue(self.onlySIP.grep("access-list acl762 line 2 extended permit ip 192.168.2.0 255.255.255.0 10.221.34.0 255.255.255.0 (hitcnt=9) 0xfe82efcc"))
        self.assertFalse(self.onlySIP.grep("access-list acl762 line 2 extended permit ip 192.168.0.0 255.255.255.0 10.221.34.0 255.255.255.0 (hitcnt=9) 0xfe82efcc"))

        self.assertFalse(self.onlySIP.grep("just some random text"))

    def testMatchDIP(self):
        self.assertTrue(self.onlyDIP.grep("10 permit udp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertFalse(self.onlyDIP.grep("10 permit udp 10.221.224.120/29 eq 4711 224.2.3.102/16 eq 4711"))

        self.assertFalse(self.onlyDIP.grep("just some random text"))
        
    def testMatchIP(self):
        grepper = ACLGrepper(None, None, None, None, "ip")
        
        self.assertTrue(grepper.grep("10 permit ip 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertFalse(grepper.grep("10 permit icmp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertFalse(grepper.grep("10 permit udp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertFalse(grepper.grep("10 permit tcp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        
        
    def testMatchICMP(self):
        grepper = ACLGrepper(None, None, None, None, "icmp")
        
        self.assertTrue(grepper.grep("10 permit ip 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertTrue(grepper.grep("10 permit icmp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertFalse(grepper.grep("10 permit udp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertFalse(grepper.grep("10 permit tcp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        
    def testMatchUDP(self):
        grepper = ACLGrepper(None, None, None, None, "udp")
        
        self.assertTrue(grepper.grep("10 permit ip 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertFalse(grepper.grep("10 permit icmp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertTrue(grepper.grep("10 permit udp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertFalse(grepper.grep("10 permit tcp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        
    def testMatchTCP(self):
        grepper = ACLGrepper(None, None, None, None, "tcp")
        
        self.assertTrue(grepper.grep("10 permit ip 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertFalse(grepper.grep("10 permit icmp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertFalse(grepper.grep("10 permit udp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertTrue(grepper.grep("10 permit tcp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))

if __name__ == '__main__':
    unittest.main()
