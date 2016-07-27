##!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  traceroute.py
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


import socket
import struct
import sys
import os


def TraceRoute(dest_addr):
    #dest_name = socket.gethostbyname(dest_addr)
    port = 33434
    max_hops = 30
    icmp = socket.getprotobyname('icmp')
    udp = socket.getprotobyname('udp')
    ttl = 1
    hopslist = []
    iphops = []
    while True:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        
        # Build the GNU timeval struct (seconds, microseconds)
        timeout = struct.pack("ll", 5, 0)
        
        # Set the receive timeout so we behave more like regular traceroute
        recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)
        
        recv_socket.bind(("", port))
        #sys.stdout.write(" %d  " % ttl)
        send_socket.sendto("", (dest_addr, port))
        curr_addr = None
        curr_name = None
        finished = False
        tries = 3
        while not finished and tries > 0:
            try:
                _, curr_addr = recv_socket.recvfrom(512)
                finished = True
                curr_addr = curr_addr[0]
                try:
                    curr_name = socket.gethostbyaddr(curr_addr)[0]
                except socket.error:
                    curr_name = curr_addr
            except socket.error as (errno, errmsg):
                tries = tries - 1
                #sys.stdout.write("* ")
        
        if tries <=0 and curr_addr is None:
			break
        send_socket.close()
        recv_socket.close()
        
        if not finished:
            pass
        
        if curr_addr is not None:
			if curr_addr in iphops:
				break
			curr_host = { 
			'hostname' : curr_name,
			'address' : curr_addr,
			'mac' : "",
			'hop_nbr' :	ttl
			} 
			hopslist.append(curr_host)
			iphops.append(curr_addr)
        else:
            curr_host = ""

        ttl += 1
        
        if curr_addr == dest_addr or ttl > max_hops:
            break
    return hopslist,iphops 	
    
#def main(args):
	##list1 = TraceRoute('192.168.178.68')
	#print TraceRoute('192.168.178.1')
	##print list1 
	
	#return 0
#if __name__ == '__main__':
    #import sys
    #sys.exit(main(sys.argv))
