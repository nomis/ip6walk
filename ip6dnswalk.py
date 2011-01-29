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
import dns.resolver
import sys

nibbles = ["{0:x}".format(i) for i in range(0, 16)]
arpa = "ip6.arpa."

def walk(zone):
	hosts = {}
	for nibble in nibbles:
		try:
			name = nibble + "." + zone
			answers = dns.resolver.query(name + "." + arpa, "PTR")
			hosts[name] = [ptr.target.to_text() for ptr in answers]
		except dns.resolver.NoAnswer:
			if len(name) < 63:
				hosts.update(walk(name))
		except dns.resolver.NXDOMAIN:
			pass
	return hosts

print(walk(sys.argv[1]))
