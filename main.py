#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  main.py
#  
#  Copyright 2016 root <root@kali>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  
#  

import plugin
import traceroute

def main(args):
	hostslist = plugin.hosts_dis('localhost','5984','scan1')
	print "list of host: %s" %hostslist[0:len(hostslist)]
	hopslist = traceroute.tracrout(hostslist[1])
	if len(hopslist)== 0:
		print "no route for this host"
	 
	#hopslist = traceroute.tracrout('172.217.19.110')
	print "\nlist of hops :%s " %hopslist[0:len(hopslist)]
	
	return 0

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
