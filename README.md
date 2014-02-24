ACLGrep
=======

Description
-----------

This is a simple script to easily grep ACL control files from various sources.

It knows about IP addresses and subnet masks providing some advantage over using the standard grep command.

If you are looking for a certain IP address all lines whose subnets contain the IP address will match.
Additionally you can filter for ports and give different parameters for source and destination.


Usage
-----

Basic usage information is available on the command line when using the -h oder --help switch.

	Usage: aclgrep.py [options] [file, file, ...]
	
	Options:
	  -h, --help            show this help message and exit
	  -a, --any             Match ACLs with 'any', too
	  -i SOURCE_IP, --sip=SOURCE_IP
	                        Source IP to look for
	  -p SOURCE_PORT, --sport=SOURCE_PORT
	                        Source port to look for
	  -I DESTINATION_IP, --dip=DESTINATION_IP
	                        Destination IP to look for
	  -P DESTINATION_PORT, --dport=DESTINATION_PORT
	                        Destination port to look for
	  -o PROTOCOL, --proto=PROTOCOL
	                        Protocol to look for


Details
-------

One goal was to make the script as portable as possible:

 - everything you need is a somewhat recent Python installation
 - no installation required
 - single file


To use this you only need the `aclgrep.py` script from the main directory. All other files are test cases used during development.


Important note: This is still work in progress, so expect errors to occur!


