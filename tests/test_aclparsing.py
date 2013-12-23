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
        self.parser.next_line("access-list acl761 line 1 extended permit ip 165.34.0.0 155.155.0.0 10.111.34.0 155.155.155.0 (hitcnt=0) 0xebc9df74")
        self.assertEqual("165.34.0.0 155.155.0.0", self.parser.source_net)
        self.assertEqual("10.111.34.0 155.155.155.0", self.parser.destination_net)

        self.parser.next_line("access-list acl761 line 1 extended permit ip 165.34.0.0/16 10.111.34.0/14 (hitcnt=0) 0xebc9df74")
        self.assertEqual("165.34.0.0/16", self.parser.source_net)
        self.assertEqual("10.111.34.0/14", self.parser.destination_net)

        self.parser.next_line("permit udp 10.111.88.66 0.0.0.1 eq 4711 host 114.0.0.1 eq 4711")
        self.assertEqual("10.111.88.66 0.0.0.1", self.parser.source_net)
        self.assertEqual("114.0.0.1/32", self.parser.destination_net)

        # mixed cases
        self.parser.next_line("permit udp 10.111.88.66 0.0.0.1 eq 4711 10.111.34.0/14 eq 4711")
        self.assertEqual("10.111.88.66 0.0.0.1", self.parser.source_net)
        self.assertEqual("10.111.34.0/14", self.parser.destination_net)

        self.parser.next_line("permit udp 10.111.34.0/14 eq 4711 10.111.88.66 0.0.0.1 eq 4711 ")
        self.assertEqual("10.111.34.0/14", self.parser.source_net)
        self.assertEqual("10.111.88.66 0.0.0.1", self.parser.destination_net)

        # host cases
        self.parser.next_line("access-list 132 permit gre host 195.143.113.118 host 111.168.171.55")
        self.assertEqual("195.143.113.118/32", self.parser.source_net)
        self.assertEqual("111.168.171.55/32", self.parser.destination_net)

        # any cases
        self.parser.next_line("50 deny ip any 10.111.114.117/32")
        self.assertEqual("any", self.parser.source_net)
        self.assertEqual("10.111.114.117/32", self.parser.destination_net)

        self.parser.next_line("50 deny ip 10.111.114.0/0.0.0.155 any")
        self.assertEqual("10.111.114.0/0.0.0.155", self.parser.source_net)
        self.assertEqual("any", self.parser.destination_net)

    def testSourceAndDestPort(self):
        self.parser.next_line("permit udp 10.111.88.66 0.0.0.1 eq 4711 host 114.0.0.1 eq 4711")
        self.assertEqual("10.111.88.66 0.0.0.1", self.parser.source_net)
        self.assertEqual("114.0.0.1/32", self.parser.destination_net)

        self.parser.next_line("permit udp 10.111.88.66 0.0.0.1 eq 4711 10.111.34.0/14 eq 1986")
        self.assertEqual("eq 4711", self.parser.source_port)
        self.assertEqual("eq 1986", self.parser.destination_port)

        self.parser.next_line("permit udp 10.111.88.66 0.0.0.1 eq 198 945 10.111.34.0/14 eq 1986 6789 11103")
        self.assertEqual("eq 198 945", self.parser.source_port)
        self.assertEqual("eq 1986 6789 11103", self.parser.destination_port)

        self.parser.next_line("permit udp 10.111.34.0/14 range 4711 1045 10.111.88.66 0.0.0.1 gt 4711 ")
        self.assertEqual("range 4711 1045", self.parser.source_port)
        self.assertEqual("gt 4711", self.parser.destination_port)

        # any cases
        self.parser.next_line("access-list acl761 line 3 extended permit tcp any host 10.114.6.135 eq ssh")
        self.assertEqual("any", self.parser.source_port)
        self.assertEqual("eq ssh", self.parser.destination_port)

        self.parser.next_line("50 deny udp 10.111.114.0/0.0.0.155 neq 1035 any")
        self.assertEqual("neq 1035", self.parser.source_port)
        self.assertEqual("any", self.parser.destination_port)

    def testProtocol(self):
        self.parser.next_line("permit udp 10.111.88.66 0.0.0.1 eq 4711 host 114.0.0.1 eq 4711")
        self.assertEqual("udp", self.parser.protocol)
        self.parser.next_line("access-list acl761 line 3 extended permit tcp any host 10.114.6.135 eq ssh")
        self.assertEqual("tcp", self.parser.protocol)
        self.parser.next_line("40 deny icmp any 10.111.114.0/32")
        self.assertEqual("icmp", self.parser.protocol)
        self.parser.next_line("40 deny ip any 10.111.114.0/32")
        self.assertEqual("ip", self.parser.protocol)

if __name__ == '__main__':
    unittest.main()
