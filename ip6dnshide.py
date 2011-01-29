#!/usr/bin/env python
# encoding: utf-8
#
#	ip6dnshide - hides empty terminals in an ip6.arpa zone (preventing walking)
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
import re
import uuid

data = re.compile("^([^@;$ 	][^ 	]+)[ 	]")
rrs = {}
secret = str(uuid.uuid4())

def scan(file):
	lines = []
	for line in [line.rstrip() for line in file]:
		lines = lines + [line] + hide(line)
	return lines

def push(host, lines):
	global rrs, secret

	# create secret wildcard RR (being able to query for
	# this exact MX record makes it possible to infer NXDOMAIN
	# and allow zone walking)
	rr = ".".join([secret, "*"] + host) + " MX 0 ."
	if rr not in rrs:
		lines.append(rr)
		rrs[rr] = True

def hide(line):
	global rrs
	lines = []
	match = data.match(line)
	if match is not None:
		host = match.group(1).split(".")[1:]

		# add top-level wildcard RR
		if len(rrs) == 0:
			push([], lines)

		# add wildcard RRs between RRs
		while len(host) > 0:
			push(host, lines)
			host = host[1:]
	return lines

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Hides empty terminals in an ip6.arpa zone (preventing walking)')
	parser.add_argument('filename', help='Zone file')
	args = parser.parse_args()

	with open(args.filename, "r") as f:
		for line in scan(f):
			print(line)

	parser.exit()
