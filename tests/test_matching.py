#!/usr/bin/env python
# encoding: utf-8

import sys
import unittest

# import aclgrep code from one directory above
sys.path.append("..")
from aclgrep import ACLGrepper

class matching(unittest.TestCase):

    def setUp(self):
        pass

    def testMatchSIP(self):
        grepper = ACLGrepper("192.168.2.12")
        self.assertTrue(grepper.grep("access-list acl762 line 2 extended permit ip 192.168.2.0 255.255.255.0 10.221.34.0 255.255.255.0 (hitcnt=9) 0xfe82efcc"))
        self.assertFalse(grepper.grep("access-list acl762 line 2 extended permit ip 192.168.0.0 255.255.255.0 10.221.34.0 255.255.255.0 (hitcnt=9) 0xfe82efcc"))

        self.assertFalse(grepper.grep("just some random text"))

    def testMatchSPort(self):
        grepper = ACLGrepper("192.168.2.12", "123")
        
        # any
        self.assertTrue(grepper.grep("10 permit udp 192.168.2.0/24 any 224.0.0.102/32 eq 4711"))

        # eq
        self.assertFalse(grepper.grep("10 permit udp 192.168.2.0/24 eq 4711 224.0.0.102/32 eq 4711"))
        self.assertTrue(grepper.grep("10 permit udp 192.168.2.0/24 eq 123 224.0.0.102/32 eq 4711"))
        self.assertFalse(grepper.grep("10 permit udp 192.168.2.0/24 eq 4711 224.0.0.102/32 eq 123"))
        self.assertTrue(grepper.grep("10 permit udp 192.168.2.0/24 eq 88 99 123 125 224.0.0.102/32 eq 4711"))

        # neq
        self.assertTrue(grepper.grep("10 permit udp 192.168.2.0/24 neq 4711 224.0.0.102/32 neq 4711"))
        self.assertFalse(grepper.grep("10 permit udp 192.168.2.0/24 neq 123 224.0.0.102/32 neq 4711"))
        self.assertTrue(grepper.grep("10 permit udp 192.168.2.0/24 neq 4711 224.0.0.102/32 neq 123"))

        # gt
        self.assertFalse(grepper.grep("10 permit udp 192.168.2.0/24 gt 123 224.0.0.102/32 eq 4711"))
        self.assertTrue(grepper.grep("10 permit udp 192.168.2.0/24 gt 122 224.0.0.102/32 eq 4711"))
        self.assertFalse(grepper.grep("10 permit udp 192.168.2.0/24 gt 4711 224.0.0.102/32 gt 90"))

        # lt
        self.assertFalse(grepper.grep("10 permit udp 192.168.2.0/24 lt 123 224.0.0.102/32 eq 4711"))
        self.assertTrue(grepper.grep("10 permit udp 192.168.2.0/24 lt 124 224.0.0.102/32 lt 4711"))
        self.assertFalse(grepper.grep("10 permit udp 192.168.2.0/24 lt 100 224.0.0.102/32 lt 900"))

        # range
        self.assertFalse(grepper.grep("10 permit udp 192.168.2.0/24 range 100 120 123 224.0.0.102/32 eq 4711"))
        self.assertFalse(grepper.grep("10 permit udp 192.168.2.0/24 range 130 150 123 224.0.0.102/32 eq 4711"))
        self.assertTrue(grepper.grep("10 permit udp 192.168.2.0/24 range 100 140 123 224.0.0.102/32 eq 4711"))
        self.assertFalse(grepper.grep("10 permit udp 192.168.2.0/24 range 100 120 123 224.0.0.102/32 range 100 150"))

        self.assertFalse(grepper.grep("just some random text"))

    def testMatchDIP(self):
        grepper = ACLGrepper(None, None, "224.1.156.12")
        self.assertTrue(grepper.grep("10 permit udp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertFalse(grepper.grep("10 permit udp 10.221.224.120/29 eq 4711 224.2.3.102/16 eq 4711"))

        self.assertFalse(grepper.grep("just some random text"))
        
    def testMatchIP(self):
        grepper = ACLGrepper(None, None, None, None, "ip")
        
        self.assertTrue(grepper.grep("10 permit ip 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertFalse(grepper.grep("10 permit icmp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertFalse(grepper.grep("10 permit udp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertFalse(grepper.grep("10 permit tcp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))

        self.assertFalse(grepper.grep("just some random text"))

    def testMatchICMP(self):
        grepper = ACLGrepper(None, None, None, None, "icmp")
        
        self.assertTrue(grepper.grep("10 permit ip 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertTrue(grepper.grep("10 permit icmp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertFalse(grepper.grep("10 permit udp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertFalse(grepper.grep("10 permit tcp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))

        self.assertFalse(grepper.grep("just some random text"))
        
    def testMatchUDP(self):
        grepper = ACLGrepper(None, None, None, None, "udp")
        
        self.assertTrue(grepper.grep("10 permit ip 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertFalse(grepper.grep("10 permit icmp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertTrue(grepper.grep("10 permit udp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertFalse(grepper.grep("10 permit tcp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))

        self.assertFalse(grepper.grep("just some random text"))
        
    def testMatchTCP(self):
        grepper = ACLGrepper(None, None, None, None, "tcp")
        
        self.assertTrue(grepper.grep("10 permit ip 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertFalse(grepper.grep("10 permit icmp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertFalse(grepper.grep("10 permit udp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertTrue(grepper.grep("10 permit tcp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))

        self.assertFalse(grepper.grep("just some random text"))
        
if __name__ == '__main__':
    unittest.main()
