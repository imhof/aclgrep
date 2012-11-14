#!/usr/bin/env python

import socket, struct, sys, re

def bit_print(number):
	'''Prints the given number as 32 digit binary.'''
	print bin(number)[2:].rjust(32,'0')

def ip_to_bits(address):
	return struct.unpack("!L", socket.inet_aton(address))[0]

def subnetmask_to_bits(pattern):
	parts = pattern.split("/")
	net = ip_to_bits(parts[0])
	netmask = 0xffffffff ^ ip_to_bits(parts[1])
	return net | netmask
	
def cidr_to_bits(pattern):
	parts = pattern.split("/")
	net = ip_to_bits(parts[0])	
	netmask = (1 << (32-int(parts[1])))-1
	return net | netmask


def tests():
	'''Run a few tests.'''
	bit_print(subnetmask_to_bits("192.168.2.0/255.255.255.0"))
	bit_print(subnetmask_to_bits("192.168.2.0/255.255.252.0"))
	bit_print(subnetmask_to_bits("10.0.0.0/255.0.0.0"))

	bit_print(cidr_to_bits("192.168.2.0/24"))
	bit_print(cidr_to_bits("192.168.2.0/22"))
	bit_print(cidr_to_bits("10.0.0.0/8"))
	
if len(sys.argv) < 2:
	print "USAGE: aclgrep.py ip_adress [files, ...]"
	exit()

ip_address = ip_to_bits(sys.argv[1])

mask_re = re.compile(r"\D(\d+\.\d+\.\d+\.\d+\/\d+\.\d+\.\d+\.\d+)\D")
cidr_re = re.compile(r"\D(\d+\.\d+\.\d+\.\d+\/\d+)\D")

for arg in sys.argv[2:]:
	file = open(arg,"r")
	for line in file.readlines():
		m = mask_re.search(line)
		if m:
			if subnetmask_to_bits(m.group(1)) & ip_address == ip_address:
				print arg + ":" + line
		else:
			m = cidr_re.search(line)
			if m:
				if cidr_to_bits(m.group(1)) & ip_address == ip_address:
					print arg + ":" + line
