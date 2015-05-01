#!/usr/bin/env python
# encoding: utf-8
# Copyright 2013 Steffen Imhof, licensed under the MIT License (MIT)

import sys
import unittest

# import aclgrep code from one directory above
sys.path.append("..")
from aclgrep import ACLGrepper

class matching(unittest.TestCase):

    def setUp(self):
        pass
        
    def testMatchAny(self):
        grepper = ACLGrepper("192.168.2.12", None, None, None, None, True)
        self.assertTrue(grepper.grep("access-list aclXFG line 46 extended deny udp any any eq netbios-ns (hitcnt=920296) 0x4c3b867e"))
        self.assertTrue(grepper.grep("access-list aclXFG line 46 extended deny udp any host 10.1.1.1 eq netbios-ns (hitcnt=920296) 0x4c3b867e"))
        self.assertFalse(grepper.grep("access-list aclXFG line 46 extended deny udp host 10.1.1.1 any eq netbios-ns (hitcnt=920296) 0x4c3b867e"))        

    def testMatchSIP(self):
        grepper = ACLGrepper("192.168.2.12")
        self.assertTrue(grepper.grep("access-list acl762 line 2 extended permit ip 192.168.2.0 255.255.255.0 10.221.34.0 255.255.255.0 (hitcnt=9) 0xfe82efcc"))
        self.assertFalse(grepper.grep("access-list acl762 line 2 extended permit ip 192.168.0.0 255.255.255.0 10.221.34.0 255.255.255.0 (hitcnt=9) 0xfe82efcc"))
        self.assertFalse(grepper.grep("access-list aclXFG line 46 extended deny udp any any eq netbios-ns (hitcnt=920296) 0x4c3b867e"))

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
        self.assertFalse(grepper.grep("access-list aclXFG line 46 extended deny udp any any eq netbios-ns (hitcnt=920296) 0x4c3b867e"))

        self.assertFalse(grepper.grep("just some random text"))
        
    def testMatchIP(self):
        grepper = ACLGrepper(None, None, None, None, "ip")
        
        self.assertTrue(grepper.grep("10 permit ip 10.221.224.120/29 224.1.2.102/16"))
        self.assertFalse(grepper.grep("10 permit icmp 10.221.224.120/29 224.1.2.102/16"))
        self.assertFalse(grepper.grep("10 permit udp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertFalse(grepper.grep("10 permit tcp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))

        self.assertFalse(grepper.grep("just some random text"))

    def testMatchICMP(self):
        grepper = ACLGrepper(None, None, None, None, "icmp")
        
        self.assertTrue(grepper.grep("10 permit ip 10.221.224.120/29 224.1.2.102/16"))
        self.assertTrue(grepper.grep("10 permit icmp 10.221.224.120/29 224.1.2.102/16"))
        self.assertFalse(grepper.grep("10 permit udp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertFalse(grepper.grep("10 permit tcp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))

        self.assertFalse(grepper.grep("just some random text"))
        
    def testMatchUDP(self):
        grepper = ACLGrepper(None, None, None, None, "udp")
        
        self.assertTrue(grepper.grep("10 permit ip 10.221.224.120/29 224.1.2.102/16"))
        self.assertFalse(grepper.grep("10 permit icmp 10.221.224.120/29 224.1.2.102/16"))
        self.assertTrue(grepper.grep("10 permit udp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertFalse(grepper.grep("10 permit tcp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))

        self.assertFalse(grepper.grep("just some random text"))
        
    def testMatchTCP(self):
        grepper = ACLGrepper(None, None, None, None, "tcp")
        
        self.assertTrue(grepper.grep("10 permit ip 10.221.224.120/29 224.1.2.102/16 "))
        self.assertFalse(grepper.grep("10 permit icmp 10.221.224.120/29 224.1.2.102/16"))
        self.assertFalse(grepper.grep("10 permit udp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertTrue(grepper.grep("10 permit tcp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))

        self.assertFalse(grepper.grep("just some random text"))

    def testPortsOnly(self):
        grepper = ACLGrepper(None, "4711", None, "124")

        self.assertFalse(grepper.grep("10 permit udp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 4711"))
        self.assertFalse(grepper.grep("10 permit tcp 10.221.224.120/29 eq 124 224.1.2.102/16 eq 124"))
        self.assertTrue(grepper.grep("10 permit tcp 10.221.224.120/29 eq 4711 224.1.2.102/16 eq 124"))

    def testMatchReal(self):
        grepper = ACLGrepper("10.221.216.201", "5401", "10.221.69.143", "1024")

        self.assertTrue(grepper.grep("permit tcp 10.221.216.200 0.0.0.1 range 5400 5413 host 10.221.69.143 gt 1023 established"))
        self.assertFalse(grepper.grep("permit tcp 10.221.216.200 0.0.0.1 gt 1023 host 10.221.69.143 eq 22"))



if __name__ == '__main__':
    unittest.main()
