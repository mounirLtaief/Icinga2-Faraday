#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  TraceRoute.py
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
import sys
import struct    
class TraceRoute(object):
       
	BADDR = "0.0.0.0" # default bind address - (all IPs)
	PORT = 33434 # default port
	ICMP = socket.getprotobyname('icmp')
	UDP = socket.getprotobyname('udp')
     
	desternation = ""
	ttl = 0 # we inrecement this by one each time.    
     
        # sockets
	reciever = None
	sender = None
     
        # finished?
	finished = False
     
	def __init__(self, desternation):
		self.desternation = socket.gethostbyname(desternation)   
		self.reciever = socket.socket(socket.AF_INET, socket.SOCK_RAW, self.ICMP)
		self.sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, self.UDP)
        # Build the GNU timeval struct (seconds, microseconds)
		
		timeout = struct.pack("ll", 5, 0)  
            # bind to reciever so we can listen for replies
		self.reciever.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)
		self.reciever.bind((self.BADDR, self.PORT))
     
	def next_server(self):
		#Connects to next server 1 hop away from current server (i.e. server[ttl + 1]) 
		if self.finished:
                # we have nothing to do, just return
			return 
     
            # first job increment the ttl on the socket
		self.ttl += 1
		self.sender.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)   
		self.sender.sendto("", (self.desternation, self.PORT))
		
		
		#if self.reciever.recvfrom(512) is None:
			#self.finished = True
			#return
		
		#current_server = self.reciever.recvfrom(512)[1][0] # get 512 bytes from the reciever
		#self.display(current_server)
		
		tries = 1
		finished_1 = False
		curr_add = None
		print tries
		while not finished_1 and tries > 0 :
			try:
				_, curr_add = self.reciever.recvfrom(512)
				current_server = self.reciever.recvfrom(512)[1][0] # get 512 bytes from the reciever
				self.display(current_server)
				finished_1 = True
			except socket.error as (errno, errmsg):
				self.finished = True
				tries = tries -  1
				return	
				
		print tries	
		if tries <=0 and curr_add is None :
			self.finished = True
			return	
     
		if current_server == self.desternation:
			self.finished = True
     
	def display(self, address):
		""" Gets the hostname (if we can) and displays """
		try:
			name = socket.gethostbyaddr(address)[0]
			print "%s) %s (%s)" % (self.ttl, name, address)
		except socket.error:
                # we couldn't - we'll just tell them the IP address
			print "%s) %s" % (self.ttl, address)
           
	def __del__(self):
		""" Be good and close our sockets """
		try:
			self.reciever.close()
		except socket.error:
                # already closed
			pass
     
		try:
			self.sender.close()
		except socket.error:
                # already closed
			pass
     
def main(args):
	tracert = TraceRoute('192.168.178.50')
	while not tracert.finished:
		tracert.next_server()
	return 0
if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
       

