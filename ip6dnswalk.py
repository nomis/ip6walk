#!/usr/bin/env python
# encoding: utf-8
#
#	ip6dnswalk - walks ip6.arpa tree for a given IPv6 prefix
#
#	Copyright ©2011 Simon Arlott
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License v2
#	as published by the Free Software Foundation.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#	Or, point your browser to http://www.gnu.org/copyleft/gpl.html

from __future__ import print_function
import argparse
import binascii
import dns.exception
import dns.flags
import dns.inet
import dns.resolver
import sys

nibbles = ["{0:x}".format(i) for i in range(0, 16)]
arpa = ["ip6.arpa."]

def to_ip6(host):
	host = [list(reversed(host[i-4:i])) for i in range(32, 0, -4)]
	return ":".join(["".join(block) for block in host])

def walk(zone, verbose=False, timeout=True):
	global res
	hosts = {}
	for nibble in nibbles:
		try:
			host = [nibble] + zone

			if verbose:
				print("".join(reversed(host)), file=sys.stderr, end=" ")

			answers = res.query(".".join(host + arpa), "PTR")

			if len(host) < 32:
				# Handle answers for PTRs not at correct host length as NoAnswer
				raise dns.resolver.NoAnswer

			if verbose:
				count = len(answers)
				print("{0} PTR RR{1}".format(count, "" if count == 1 else "s"), file=sys.stderr)

			hosts[to_ip6(host)] = [ptr.target.to_text() for ptr in answers]
		except dns.resolver.NoAnswer:
			if verbose:
				print("NoAnswer", file=sys.stderr)

			if len(host) < 32:
				# If there are 3 NSEC3 records, then this is actually an NXDOMAIN
				# If there is 1 NSEC3 record, then something does exist below
				# Online NSEC3 may only return 1 record in all scenarios
				#
				# Further options for exposing data would involve creating NSEC3
				# hashes for all nibble values and comparing them to the NSEC3 RRs
				hosts.update(walk(host, verbose, timeout))
		except dns.resolver.NXDOMAIN:
			if verbose:
				print("NXDOMAIN", file=sys.stderr)
		except dns.resolver.Timeout:
			if timeout:
				if not verbose:
					print("".join(reversed(host)) + " Timeout", file=sys.stderr)
				sys.exit(1)
			if verbose:
				print("Timeout", file=sys.stderr)
	return hosts

def from_prefix(parser, args):
	try:
		(host, size) = args.prefix.split("/", 1)
		host = list(binascii.hexlify(dns.inet.inet_pton(dns.inet.AF_INET6, host)))
		size = int(size)
	except ValueError:
		parser.error("Prefix missing subnet size")
	except dns.exception.SyntaxError:
		parser.error("Invalid IPv6 address")

	if size not in range(0, 128, 4):
		parser.error("Unsupported prefix size, must be on a 4-bit boundary in the range /0../124")

	return list(reversed(host[:size/4]))

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Walks ip6.arpa tree for a given IPv6 prefix')
	parser.add_argument('-i', '--ignore-timeout', action='store_true', help='Don\'t abort on timeout')
	parser.add_argument('-r', '--resolver', action='append', help='Use specified resolver(s)')
	parser.add_argument('-v', '--verbose', action='store_true', help='Outputs every PTR query performed to stderr')
	parser.add_argument('prefix', help='IPv6 prefix with subnet on 4-bit boundary in the range /0../124')
	args = parser.parse_args()

	if args.resolver is not None:
		res = dns.resolver.Resolver(configure=False)
		res.nameservers = args.resolver
	else:
		res = dns.resolver.Resolver()
	res.use_edns(0, dns.flags.DO, 4096)

	hosts = walk(from_prefix(parser, args), args.verbose, not args.ignore_timeout)
	for host in sorted(hosts.keys()):
		print(host, " ".join(sorted(hosts[host])))

	parser.exit()
