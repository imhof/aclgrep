#!/usr/bin/env python

import sys, re

class Rules:
    def __init__(self):
        self.base_rule = re.compile("(.*)\->(.*)")
        self.parsed_rules = []
        
    def read_from(self, lines):
        for line in lines:
            m = self.base_rule.match(line)
            if m:
                rule = { "pattern": m.group(1).strip(), "output": m.group(2).strip() }
                print(rule)
            else:
                print("Invalid config line: ", line)
                return False             
        return True
                
                
if __name__ == '__main__':
    lines = ["->", "test -> bla", "xxx", "-"];
    r = Rules()
    r.read_from(lines)
