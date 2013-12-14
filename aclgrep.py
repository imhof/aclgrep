#!/usr/bin/env python

'''Simple script to grep for networks (net + wildcard, subnetmask or CIDR) containing a given IP address.'''

import socket, struct, sys, re, fileinput
from optparse import OptionParser


class ACLParser:
    """Helper class to parse an ACL file line by line.
       This will find out protocol, networks and ports for each line and keeps track
       of the name of the current ACL rule."""
    source_net = None
    source_port = None
    destination_net = None
    destination_port = None
    protocol = None

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
        r"\s(n?eq\s+\d+)",
        r"\s(n?eq\s+\S+)",
        r"\s(gt\s+\d+)",
        r"\s(lt\s+\d+)",
        r"\s(any)",
    ]

    protocol_patterns = [
        r"\s(icmp|ip|tcp|udp)\s"
    ]

    def __init__(self):
        # compile all patterns to regexes
        self.net_patterns = [re.compile(p) for p in self.net_patterns]
        self.port_patterns = [re.compile(p) for p in self.port_patterns]
        self.protocol_patterns = [re.compile(p) for p in self.protocol_patterns]

    def reset_transients(self):
        self.source_net = None
        self.source_port = None
        self.destination_net = None
        self.destination_port = None
        self.protocol = None

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

    def assign_source_dest(self, hits):
        """Take the first and last one to weed out the invalid hits."""
        result = [None, None]
        sorted_keys = sorted(hits.keys())
        if len(sorted_keys) > 0:
            result[0] = hits[sorted_keys[0]]
        if len(sorted_keys) > 1:
            result[1] = hits[sorted_keys[-1]]
        return result

    def next_line(self, line):
        self.reset_transients()

        # first look for all net matches
        hits = self.match_patterns(line, self.net_patterns)
        (self.source_net, self.destination_net) = self.assign_source_dest(hits)

        # second look for all port matches
        hits = self.match_patterns(line, self.port_patterns)
        (self.source_port, self.destination_port) = self.assign_source_dest(hits)

        # look for all protocol matches
        hits = self.match_patterns(line, self.protocol_patterns)
        if len(hits) == 1:
            self.protocol = hits.popitem()[1]

class ACLGrepper:
    '''The main class which handles the grep process as a whole.'''

    # Configuration
    # Add special patterns to detect IP networks here
    cidr_patterns = [
        r"\D(\d+\.\d+\.\d+\.\d+\/\d+)\D",
    ]
    mask_patterns = [
        r"\D(\d+\.\d+\.\d+\.\d+\D\d+\.\d+\.\d+\.\d+)\D",
    ]
    aclname_patterns = [
        r"ip access-list( extended)? (.*)$",
    ]
    splitter = re.compile(r"[^0-9.]")

    last_aclname = "(unknown)"

    ip_string = ""
    ip_address = 0
    match_any = False


    def __init__(self, ip_string, match_any):
        # compile all patterns to regexes
        self.mask_patterns    = [ re.compile(p) for p in self.mask_patterns ]
        self.cidr_patterns    = [ re.compile(p) for p in self.cidr_patterns ]
        self.aclname_patterns = [ re.compile(p) for p in self.aclname_patterns ]

        self.ip_string = ip_string
        self.ip_address = self.ip_to_bits(ip_string)

        self.match_any = match_any

    def ip_to_bits(self, address):
        '''Turns an IP address in dot notation into a single long value.'''

        # Fixup IP addresses with leading zeros
        fixed_address = ".".join([str(int(x)) for x in address.split(".")])

        try:
            return struct.unpack("!L", socket.inet_aton(fixed_address))[0]
        except socket.error:
            raise ValueError("Invalid IP address")

    def ip_in_net(self, ip, net):
        '''Checks if an IP adress is contained in a network described by a pair (net address, subnetmask).
           All values are given as longs.'''
        return (net[0] & net[1] == ip & net[1])

    def ip_and_mask_to_pair(self, pattern):
        '''Takes a mask pattern and creates a pair (net address, subnetmask) from it.
           Detects automatically if the mask is a subnetmask or a wildcard mask, assuming the bits are
           set continuously in either.'''
        parts = re.split(self.splitter, pattern)
        net = self.ip_to_bits(parts[0])
        net_or_wildcard = self.ip_to_bits(parts[1])

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

    def ip_and_cidr_to_pair(self, pattern):
        '''Takes a CIDR pattern and creates a pair (net address, subnetmask) from it.'''
        parts = pattern.split("/")
        net = self.ip_to_bits(parts[0])
        wildcard = (1 << (32-int(parts[1])))-1
        return (net, 0xffffffff ^ wildcard)

    def grep(self, line):
        line_has_matched = False

        # check for ACL name
        for p in self.aclname_patterns:
            m = p.search(line)
            if m:
                self.last_aclname = m.group(2).strip()
                continue

        # check any if desired
        if self.match_any and "any" in line:
            print ("%s (%s): %s" % (fileinput.filename(), self.last_aclname , line)),
            return

        # check for the IP address directly first
        if self.ip_string in line:
            print fileinput.filename() + ":" + line,
            return

        for p in self.mask_patterns:
            m = p.search(line)
            while m:
                line_has_matched = True
                net = self.ip_and_mask_to_pair(m.group(1))
                if self.ip_in_net(self.ip_address, net):
                    print fileinput.filename() + " (" + self.last_aclname + "):" + line,
                    break
                m = p.search(line, m.start() + 1)

        # prevent CIDR matches if a mask match was already found
        if line_has_matched:
            return

        for p in self.cidr_patterns:
            m = p.search(line)
            while m:
                net = self.ip_and_cidr_to_pair(m.group(1))
                if self.ip_in_net(self.ip_address,net):
                    print fileinput.filename() + " (" + self.last_aclname + "):" + line,
                    break
                m = p.search(line, m.start() + 1)


if __name__ == '__main__':
    # check command line args
    parser = OptionParser(usage="Usage: %prog [options] ip_address [file, file, ...]")
    parser.add_option("-a", "--any", dest="match_any", action="store_true", default=False, help="Match ACLs with 'any', too")
    parser.add_option("-i", "--sip", dest="source_ip", default=None, help="Source IP to look for")
    parser.add_option("-p", "--sport", dest="source_port", default=None, help="Source port to look for")
    parser.add_option("-I", "--dip", dest="destination_ip", default=None, help="Destination IP to look for")
    parser.add_option("-P", "--dport", dest="destination_port", default=None, help="Destination port to look for")

    (options, args) = parser.parse_args()

    if len(args) < 1:
        print "USAGE: aclgrep.py [-a|--any] ip_adress file [, file, file, ...]"
        sys.exit()

    # initialize grepper and...
    grepper = ACLGrepper(args.pop(0), options.match_any)

    # ...check all lines in all files (or stdin)
    for line in fileinput.input(args):
        grepper.grep(line)
