#!/usr/bin/env python
# encoding: utf-8

import sys
import unittest

# import aclgrep code from one directory above
sys.path.append("..")
from aclgrep import ACLParser


class ACLParserTest(unittest.TestCase):

    def setUp(self):
        self.parser = ACLParser()

    def testSourceAndDestNet(self):
        self.parser.next_line("access-list acl762 line 2 extended permit ip 165.34.0.0 255.255.0.0 10.221.34.0 255.255.255.0 (hitcnt=0) 0xebc9df74")
        self.assertEqual("165.34.0.0 255.255.0.0", self.parser.source_net)
        self.assertEqual("10.221.34.0 255.255.255.0", self.parser.destination_net)

        self.parser.next_line("access-list acl762 line 2 extended permit ip 165.34.0.0/16 10.221.34.0/24 (hitcnt=0) 0xebc9df74")
        self.assertEqual("165.34.0.0/16", self.parser.source_net)
        self.assertEqual("10.221.34.0/24", self.parser.destination_net)

        self.parser.next_line("permit udp 10.221.88.66 0.0.0.1 eq 4711 host 224.0.0.2 eq 4711")
        self.assertEqual("10.221.88.66 0.0.0.1", self.parser.source_net)
        self.assertEqual("224.0.0.2", self.parser.destination_net)

        # mixed cases
        self.parser.next_line("permit udp 10.221.88.66 0.0.0.1 eq 4711 10.221.34.0/24 eq 4711")
        self.assertEqual("10.221.88.66 0.0.0.1", self.parser.source_net)
        self.assertEqual("10.221.34.0/24", self.parser.destination_net)

        self.parser.next_line("permit udp 10.221.34.0/24 eq 4711 10.221.88.66 0.0.0.1 eq 4711 ")
        self.assertEqual("10.221.34.0/24", self.parser.source_net)
        self.assertEqual("10.221.88.66 0.0.0.1", self.parser.destination_net)

        # any cases
        self.parser.next_line("50 deny ip any 10.221.224.127/32")
        self.assertEqual("any", self.parser.source_net)
        self.assertEqual("10.221.224.127/32", self.parser.destination_net)

        self.parser.next_line("50 deny ip 10.221.224.0/0.0.0.255 any")
        self.assertEqual("10.221.224.0/0.0.0.255", self.parser.source_net)
        self.assertEqual("any", self.parser.destination_net)

    def testSourceAndDestPort(self):
        self.parser.next_line("permit udp 10.221.88.66 0.0.0.1 eq 4711 host 224.0.0.2 eq 4711")
        self.assertEqual("10.221.88.66 0.0.0.1", self.parser.source_net)
        self.assertEqual("224.0.0.2", self.parser.destination_net)

        self.parser.next_line("permit udp 10.221.88.66 0.0.0.1 eq 4711 10.221.34.0/24 eq 1986")
        self.assertEqual("eq 4711", self.parser.source_port)
        self.assertEqual("eq 1986", self.parser.destination_port)

        self.parser.next_line("permit udp 10.221.34.0/24 range 4711 2045 10.221.88.66 0.0.0.1 gt 4711 ")
        self.assertEqual("range 4711 2045", self.parser.source_port)
        self.assertEqual("gt 4711", self.parser.destination_port)

        # any cases
        self.parser.next_line("access-list acl762 line 3 extended permit tcp any host 10.224.6.235 eq ssh")
        self.assertEqual("any", self.parser.source_port)
        self.assertEqual("eq ssh", self.parser.destination_port)

        self.parser.next_line("50 deny udp 10.221.224.0/0.0.0.255 neq 1035 any")
        self.assertEqual("neq 1035", self.parser.source_port)
        self.assertEqual("any", self.parser.destination_port)

if __name__ == '__main__':
    unittest.main()
