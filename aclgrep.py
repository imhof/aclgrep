#!/usr/bin/env python

'''Simple script to grep for networks (net + wildcard, subnetmask or CIDR) containing a given IP address.'''

import socket, struct, sys, re, fileinput

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


def bit_print_pair(numbers):
    '''Prints the given numbers as 32 digit binary.'''
    print bin(numbers[0])[2:].rjust(32,'0'), bin(numbers[1])[2:].rjust(32,'0')

def ip_to_bits(address):
    '''Turns an IP address in dot notation into a single long value.'''

    # Fixup IP addresses with leading zeros
    fixed_address = ".".join([str(int(x)) for x in address.split(".")])

    try:
        return struct.unpack("!L", socket.inet_aton(fixed_address))[0]
    except socket.error:
        raise ValueError("Invalid IP address")

def ip_in_net(ip, net):
    '''Checks if an IP adress is contained in a network described by a pair (net address, subnetmask).
       All values are given as longs.'''
    return (net[0] & net[1] == ip_address & net[1])

def ip_and_mask_to_pair(pattern):
    '''Takes a mask pattern and creates a pair (net address, subnetmask) from it.
       Detects automatically if the mask is a subnetmask or a wildcard mask, assuming the bits are
       set continuously in either.'''
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

if __name__ == '__main__':
    # check command line args
    if len(sys.argv) < 2:
        print "USAGE: aclgrep.py [-any] ip_adress file [, file, file, ...]"
        sys.exit()

    match_any = False
    if sys.argv[1] == "-any":
        ip_string = sys.argv[2]
        match_any = True
    else:
        ip_string = sys.argv[1]

    ip_address = ip_to_bits(ip_string)

    # compile all patterns to regexes
    mask_patterns    = [ re.compile(p) for p in mask_patterns ]
    cidr_patterns    = [ re.compile(p) for p in cidr_patterns ]
    aclname_patterns = [ re.compile(p) for p in aclname_patterns ]

    last_aclname = "(unknown)"

    # check all lines in all files (or stdin)
    for line in fileinput.input(sys.argv[(2+match_any):]):
        line_has_matched = False

        # check for ACL name
        for p in aclname_patterns:
            m = p.search(line)
            if m:
                last_aclname = m.group(2)
                continue

        # check any if desired
        if match_any and "any" in line:
            print fileinput.filename() + " (" + last_aclname + "):" + line,
            continue

        # check for the IP address directly first
        if ip_string in line:
            print fileinput.filename() + ":" + line,
            continue

        for p in mask_patterns:
            m = p.search(line)
            while m:
                line_has_matched = True
                net = ip_and_mask_to_pair(m.group(1))
                if ip_in_net(ip_address, net):
                    print fileinput.filename() + " (" + last_aclname + "):" + line,
                    break
                m = p.search(line, m.start() + 1)

        # prevent CIDR matches if a mask match was already found
        if line_has_matched:
            continue

        for p in cidr_patterns:
            m = p.search(line)
            while m:
                net = ip_and_cidr_to_pair(m.group(1))
                if ip_in_net(ip_address,net):
                    print fileinput.filename()+ " (" + last_aclname + "):" + line,
                    break
                m = p.search(line, m.start() + 1)
