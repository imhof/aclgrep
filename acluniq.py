#!/usr/bin/env python

import re
import socket
import struct
import sys
import fileinput
import itertools


# Add special patterns to detect IP networks and hosts here
# Make sure they start with the most specific, as they are tried in order
net_patterns = [
    r"host\D+(\d+\.\d+\.\d+\.\d+)",
    r"\D(\d+\.\d+\.\d+\.\d+\D\d+\.\d+\.\d+\.\d+)",
    r"\D(\d+\.\d+\.\d+\.\d+\/\d+)",
    r"\s(any)",
]

# Add special patterns to detect port descriptions here
# Make sure they start with the most specific, as they are tried in order
port_patterns = [
    r"\s(range\s+\d+\s+\d+)",
    r"\s(n?eq\s(\d+(\s|$))+)",
    r"\s(n?eq\s+\S+)",
    r"\s(gt\s+\d+)",
    r"\s(lt\s+\d+)",
    r"\s(any)",
]

protocol_patterns = [
    r"\s(icmp|ip|tcp|udp)\s"
]

type_patterns = [
    r"\s*(permit|deny)\s"
]

# potential additional information at the end of the rule
# currently only "established" is relevant
extra_patterns = [
    r"\s(established)(\s|$)"
]

# compile all patterns to regexes
net_patterns = [re.compile(p) for p in net_patterns]
port_patterns = [re.compile(p) for p in port_patterns]
protocol_patterns = [re.compile(p) for p in protocol_patterns]
extra_patterns = [re.compile(p) for p in extra_patterns]
type_patterns = [re.compile(p) for p in type_patterns]

splitter = re.compile(r"[^0-9.]")

def ip_to_bits(address):
    """Turns an IP address in dot notation into a single long value."""

    # Fixup IP addresses with leading zeros
    fixed_address = ".".join([str(int(x)) for x in address.split(".")])

    try:
        return struct.unpack("!L", socket.inet_aton(fixed_address))[0]
    except socket.error:
        raise ValueError("Invalid IP address")

def ip_in_net(ip, net):
    """Checks if an IP adress is contained in a network described by a pair (net address, subnetmask).
       All values are given as longs."""
    return net[0] & net[1] == ip & net[1]

def net_in_net(container, contained):
    """Checks if a subnet is contained in a network described by a pair (net address, subnetmask).
       All values are given as longs."""
    return (container[0] & container[1] == contained[0] & container[1]) and (container[1] <= contained[1])

def ip_and_mask_to_pair(pattern):
    """Takes a mask pattern and creates a pair (net address, subnet mask) from it.
       Detects automatically if the mask is a subnet mask or a wildcard mask, assuming the bits are
       set continuously in either."""

    if pattern == "any":
        return (0xffffffff, 0x00000000) # 0.0.0.0/0

    parts = re.split(splitter, pattern)
    net = ip_to_bits(parts[0])
    net_or_wildcard = ip_to_bits(parts[1])

    # special case full bits -> subnet mask
    if 0xffffffff == net_or_wildcard:
        return (net, 0xffffffff)

    # check if the mask is really a mask (only set bits from the right or left)
    if net_or_wildcard & (net_or_wildcard + 1) != 0:
        net_or_wildcard = 0xffffffff ^ net_or_wildcard
        if net_or_wildcard & (net_or_wildcard + 1) != 0:
            # it's not, never match
            return (0, 0xffffffff)

    return (net, 0xffffffff ^ net_or_wildcard)

def ip_and_cidr_to_pair(pattern):
    '''Takes a CIDR pattern and creates a pair (net address, subnetmask) from it.'''
    parts = pattern.split("/")
    net = ip_to_bits(parts[0])
    wildcard = (1 << (32-int(parts[1])))-1
    return (net, 0xffffffff ^ wildcard)

def net_string_to_pair(pattern):
    if pattern.find("/") == -1:
        return ip_and_mask_to_pair(pattern)
    else:
        return ip_and_cidr_to_pair(pattern)

class ACL:
    
    def __init__(self):
                
        self.proto = ""
        self.type = ""
        self.source = (0xffffffff, 0x00000000)
        self.source_port_min = 0
        self.source_port_max = 65536
        self.dest = (0xffffffff, 0x00000000)
        self.dest_port_min = 0
        self.dest_port_max = 65536
        self.extra = ""
        self.orig = ""
        
    def assign_source_dest(self, hits):
        """Take the first and last one to weed out the invalid hits."""
        result = [None, None]
        sorted_keys = sorted(hits.keys())
        if len(sorted_keys) > 0:
            result[0] = hits[sorted_keys[0]].strip()
        if len(sorted_keys) > 1:
            result[1] = hits[sorted_keys[-1]].strip()
        return result

    def match_patterns(self, line, patterns):
        """We might get invalid matches, e.g. "source_mask destination_net. This gets sorted out by taking
           the first and the last match later on."""
        hits = {}
        for p in patterns:
            m = p.search(line)
            while m:
                if not m.start() in hits:
                    hits[m.start()] = m.group(1)
                m = p.search(line, m.start() + 1)
        return hits

    def set_ports(self, basename, pattern):
        setattr(self, basename + "_port_min", 0)
        setattr(self, basename + "_port_max", 65536)

        if pattern == "any":
            pass

        # eq
        if pattern[:2] == "eq":
            setattr(self, basename + "_port_min", int(pattern[3:]))
            setattr(self, basename + "_port_max", int(pattern[3:]))

        # gt
        if pattern[:2] == "gt":
            setattr(self, basename + "_port_min", int(pattern[3:]) + 1)

        # lt
        if pattern[:2] == "lt":
            setattr(self, basename + "_port_max", int(pattern[3:]) - 1)

        # range
        if pattern[:5] == "range":
            parts = pattern.split()
            setattr(self, basename + "_port_min", int(parts[1]))
            setattr(self, basename + "_port_max", int(parts[2]))

    def read_from(self, line):

        self.orig = line
        
        # first check the type
        hits = self.match_patterns(line, type_patterns)
        if not hits:
            return False
        self.type = hits.popitem()[1]

        # now look for all net matches
        hits = self.match_patterns(line, net_patterns)
        (source, dest) = self.assign_source_dest(hits)

        if not source and not dest:
            return False
            
        try:
            # transform simple hosts into CIDR form
            if source and not "any" in source and not "/" in source and not " " in source:
                source += "/32"
            if dest and not "any" in dest and not "/" in dest and not " " in dest:
                dest += "/32"

            self.source = net_string_to_pair(source)
            self.dest = net_string_to_pair(dest)

            # second look for all port matches
            hits = self.match_patterns(line, port_patterns)
            (source_port, destination_port) = self.assign_source_dest(hits)
        
            if source_port: self.set_ports("source", source_port)
            if destination_port: self.set_ports("dest", destination_port)
        
            # look for all protocol matches
            hits = self.match_patterns(line, protocol_patterns)
            if len(hits) == 1:
                self.proto = hits.popitem()[1]

            # look for all extra matches
            hits = self.match_patterns(line, extra_patterns)
            if len(hits) == 1:
                self.extra = hits.popitem()[1]
        except:
            # catch unexpected parsing errors
            return False
        return True

    def contains(self, other):
        # check type
        if other.type != self.type:
            return False
        
        # check protocol
        if other.proto == "ip" and self.proto != "ip":
            return False
        if self.proto != "ip" and self.proto != other.proto:
            return False

        # check addresses
        if not net_in_net(self.source, other.source):
            return False
        if not net_in_net(self.dest, other.dest):
            return False

        # check ports
        if self.source_port_min > other.source_port_min:
            return False
        if self.source_port_max < other.source_port_max:
            return False
        if self.dest_port_min > other.dest_port_min:
            return False
        if self.dest_port_max < other.dest_port_max:
            return False
            
        return True
        
def simple_test():
    a = ACL()
    a2 = ACL()
    a3 = ACL()
    b = ACL()

    a.read_from("permit ip 10.0.0.0/8 any")
    a2.read_from("permit udp 10.0.0.0/8 any")
    a3.read_from("permit ip 10.223.0.0/16 any")
    b.read_from("permit tcp host 10.223.254.58 eq 81 10.224.196.100 0.0.0.3 gt 1023 established")

    print("A", vars(a))
    print("A2", vars(a2))
    print("A3", vars(a3))
    print("B", vars(b))
    
    print(a.contains(b))
    print(a2.contains(b))
    print(a3.contains(b))
    print(b.contains(a))
    print(a.contains(a3))
    print(a2.contains(a3))

    

if __name__ == '__main__':
    if len(sys.argv) < 2:
        simple_test()
        sys.exit()
    
    lines = list(fileinput.input())
    count = len(lines)
    
    acl1 = ACL()
    acl2 = ACL()
    
    for x in range(0, count):
        print x
        if not acl1.read_from(lines[x]):
            continue
            
        for y in range(x+1, count):
            if not acl2.read_from(lines[y]):
                continue
                
            if acl1.contains(acl2):
                print("XXX", lines[x], lines[y])
            
        
    

