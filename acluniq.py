#!/usr/bin/env python

import re


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

# compile all patterns to regexes
net_patterns = [re.compile(p) for p in net_patterns]
port_patterns = [re.compile(p) for p in port_patterns]
protocol_patterns = [re.compile(p) for p in protocol_patterns]



class ACL:
    
    def __init__(self):
                
        self.proto = ""
        self.source = "0.0.0.0"
        self.source_port_min = 0
        self.source_port_max = 65536
        self.dest = "0.0.0.0"
        self.dest_port_min = 0
        self.dest_port_max = 65536
        self.extra = ""
        
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

    def set_ports(self, basename, ports):
        pass

    def read_from(self, line):

        # first look for all net matches
        hits = self.match_patterns(line, net_patterns)
        (self.source, self.dest) = self.assign_source_dest(hits)

        # transform simple hosts into CIDR form
        if self.source and not "any" in self.source and not "/" in self.source and not " " in self.source:
            self.source += "/32"
        if self.dest and not "any" in self.dest and not "/" in self.dest and not " " in self.dest:
            self.dest += "/32"

        # second look for all port matches
        hits = self.match_patterns(line, port_patterns)
        (source_port, destination_port) = self.assign_source_dest(hits)
        
        set_ports("source", source_port)
        set_ports("dest", destination_port)
        
        # look for all protocol matches
        hits = self.match_patterns(line, protocol_patterns)
        if len(hits) == 1:
            self.proto = hits.popitem()[1]

    def contains(self, other):
        if self.source_port_min > other.source_port_min:
            return False
        if self.source_port_max < other.source_port_max:
            return False
        if self.dest_port_min > other.dest_port_min:
            return False
        if self.dest_port_max < other.dest_port_max:
            return False
            
        return True

if __name__ == '__main__':
    a = ACL()
    b = ACL()
    
    a.read_from("permit tcp 10.0.0.0/8 eq 80 any established")

    print ("A", vars(a))
    print ("B", vars(b))
    
    print a.contains(b)
    print b.contains(a)

