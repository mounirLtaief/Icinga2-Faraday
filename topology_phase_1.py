#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  topology_phase_1.py
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

import os 
import json
import traceroute
import Retreive_from_couchdb
import socket
from netaddr import IPNetwork
from neo4j.v1 import GraphDatabase, basic_auth

if os.name != "nt":
	import fcntl
	import struct
	def get_interface_ip(ifname):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])
		return ip

def get_ipsource():
	ip = socket.gethostbyname(socket.gethostname())
	if ip.startswith("127.") and os.name != "nt":
		interfaces = [
            "eth0",
            "eth1",
            "eth2",
            "wlan0",
            "wlan1",
            "wifi0",
            "ath0",
            "ath1",
            "ppp0",
            ]
		for ifname in interfaces:
			try:
				ip = get_interface_ip(ifname)
				break
			except IOError:
				pass
	return  ip

def verify_gate(hop,gateway,data,hopnbr) :
	
	gate = None
	exist = False
	for hops in gateway :
		if hops['address'] == hop :
			gate = hops
			exist = True
			return exist,gate
	for nod in data :
		if nod['address'] == hop :
			gate = {
			'hostname' : nod['hostname'],
			'address' : nod['address'],
			'mac': nod['mac'],
			'hop_nbr' :	hopnbr+1
			}
			exist = True
			return exist,gate
	return exist,gate

def verify_curr_host(address,data) :
	
	host = None
	exist = False	
	for nod in data :
		if nod['address'] == address :
			host = nod
			exist = True
			return exist,host
	
	return exist,host






def get_topology_links() :
	data = Retreive_from_couchdb.hosts_list('localhost','5984','scan-test123')
	data = json.loads(data)
	insert_query = '''
	UNWIND {links} AS link
	MERGE (h1:node_UP { name: link[0]['hostname'],address: link[0]['address'],mac: link[0]['mac'] })
	MERGE (h2:node_UP { name: link[1]['hostname'], address: link[1]['address'],mac: link[1]['mac']  })
	MERGE (h1)<-[:CONNECT_TO]->(h2);
	'''
	
	ip = get_ipsource()
	gateway_0 = None
	curr_host = None
	gateway_info = []
	gateway = []
	local_net = []
	node_nbr=0
	links = []
	for node in data :
		dest_addr = node['address']
		hops_info,hops_to = traceroute.TraceRoute(dest_addr)
		l= len(hops_to)
		# local network
		if l==1:
			if hops_to[0] == ip :
				local_net.append(node)
				if node['address'] == ip :
					curr_host = node
			if hops_to[0] <> ip:
				gateway_0 = node
				gate_0 = {
				'hostname' : node['hostname'],
				'address' : node['address'],
				'mac': node['mac'],
				'hop_nbr' :	l
				}
				gateway.append(gate_0)   
			
		
		#distant networks
		if l > 1 :
			hop_nbr = 0
			exist,gate = verify_gate(hops_to[0],gateway,data,hop_nbr)
			
			exist_curr = curr_host is not None
			
			if not exist_curr:
				exist_curr, curr_host = verify_curr_host(ip,data)
			if not exist_curr:
				host_info= {
				'hostname' : "localhost",
				'address' : ip,
				'mac' : " "
				}
			if exist_curr and exist :
				links.append([curr_host,gate])
			if exist_curr and not exist :
				links.append([curr_host,hops_info[0]])
				gateway.append(hops_info[0])
			if not exist_curr and  exist :
				links.append([host_info,gate])
			if not exist_curr and not exist :
				links.append([host_info,hops_info[0]])
				gateway.append(hops_info[0])

			while hop_nbr < l-1 :
				
				exist,gate = verify_gate(hops_to[hop_nbr+1],gateway,data,hop_nbr)
				if exist:
					links.append([links[len(links)-1][1],gate])
				if not exist:
					links.append([links[len(links)-1][1],hops_info[hop_nbr+1]])
					gateway.append(hops_info[hop_nbr+1])	
				hop_nbr+=1
			
			if hops_info[l-1]['address'] <> node['address'] :
				unknown_net = {
				'hostname' : "unknown network",
				'address' : "unreachable",
				'mac' : "",
				'hop_nbr' :	l+1
				}
				links.append([links[len(links)-1][1],unknown_net])
				links.append([unknown_net,node])
		node_nbr+=1
	
	# local network
	for host in local_net :
		links.append([host,gateway_0]) 
	
	driver = GraphDatabase.driver("bolt://localhost", auth=basic_auth("neo4j", "azerty159"))
	session = driver.session()	
	session.run(insert_query, parameters={"links": links})
	session.close()
	return 0
def main(args):
	get_topology_links() 
	return 0

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
