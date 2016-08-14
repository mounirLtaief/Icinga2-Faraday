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
import os 
import json
import simplejson
import plugin
import traceroute
import socket
from netaddr import IPNetwork
import topology_graph
import topology
from neo4j.v1 import GraphDatabase, basic_auth

if os.name != "nt":
	import fcntl
	import struct
	def get_interface_ip(ifname):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])
		return ip

def _verify_ipsource():
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
	#exist = ip in data
	return  ip

def _hostslist(data,gateway):
	result = []
	for i in data :
		
		#if i <> gateway and i <> 'gateway' :
		if i <> 'gateway' :
			result.append(i)
	return result

def _verifyip(ip,route) :
	if len(route)==0 :
		return False
	else:
		for k in route :
			l =len(k)
			j=0
			while j<l:
				if k[j] == ip:
					return True
				j+=1	
	return False

def main(args):
	
	'''
    First stage : traceroute 	
	'''
	data,gatewaylist,hostsnb = plugin.hosts_dis('localhost','5984','scan_test')
	
	hopslist = []
	data1 = json.loads(data)
	print simplejson.dumps(data1, sort_keys=True, indent=4)
	
	driver = GraphDatabase.driver("bolt://localhost", auth=basic_auth("neo4j", "azerty159"))
	session = driver.session()	
	#constraint_query = '''
	#create constraint on (h:`host`) assert h.`name` is unique;
	#'''
	#constraint_query1 = '''
	#create constraint on (g:`gateway`) assert g.`name` is unique;
	#'''
	insert_query = '''
	UNWIND {sources} AS sr
	UNWIND {destination} AS dst
	MERGE (h:host {name: sr[0],os: sr[1],gateway: sr[2] })
	MERGE (g:gateway {name: dst[0], os: dst[1]})
	MERGE (h)<-[:CONNECT_TO]->(g);
	'''
	insert_query1 = '''
	UNWIND {links} AS link
	MERGE (h:host {name: link[0][0],os: link[0][1],gateway: link[0][2] })
	MERGE (g:gateway {name: link[1][0], os: link[1][1]})
	MERGE (h)<-[:CONNECT_TO]->(g);
	'''
    #list of hops to the gateways
	routes = []
	for route in gatewaylist:
			routelist = []
			routelist = traceroute._traceroute(route)
			if len(routelist)>0 :
				routes.append(routelist)	
	#print routes
	exist_hosts = []
	hosts_list = []
	links = []	
	gate = []
	ip = _verify_ipsource()
	gate_comp = 0	
	
	for node in data1 :
		k = len(node)
		g=1
		# list of the existing hosts existed with traceroute and the details about gateways
		while g < k:
			if _verifyip(node[g]['ip'],routes) and node[g]['ip'] <> node[g]['gateway'] :
				exist_hosts.append([node[g]['ip'],node[g]['os'],node[g]['gateway']])
				hosts_list.append(node[g]['ip'])	
			if node[g]['ip'] == node[g]['gateway'] :
				gate.append([node[g]['ip'],node[g]['os']])
				gate_comp +=1 
			g+=1
		i=1
		# get information about the local host where the topvis installed
		if gate_comp==0 :
			gate.append([node[0]['gateway'],'unknown'])
			gate_comp +=1
		nd = []
		while i < k :
			if node[i]['ip'] <> node[i]['gateway'] :
				if node[i]['ip'] == ip :
					nd = [node[i]['ip'],node[i]['os'],node[i]['gateway']]
				links.append([[node[i]['ip'],node[i]['os'],node[i]['gateway']],gate[gate_comp-1]])
			i+=1
	
	if len(routes)>0 :
		for nexthop in routes:
			if len(nd)>0 :
				if nexthop[0] in gatewaylist :
					for gt in gate :
						if gt[0] == nexthop[0] :
							links.append([nd,gt])
							break
				else :
						links.append([nd,[nexthop[0],"unknown"]])	
			else :
				if nexthop[0] in gatewaylist :
					for gt in gate :
						if gt[0] == nexthop[0] :
							links.append([[ip,"unknown",nexthop[0]],gt])
							break
				else:
					links.append([[ip,"unknown",nexthop[0]],[nexthop[0],"unknown"]])
			l = len(nexthop)
			if l > 1 :				
				j=0
				while j < l-1:
					if nexthop[j+1] in gatewaylist :
						for gt in gate :
							if gt[0] == nexthop[j] :
								links.append([[nexthop[j],"unknown",nexthop[j+1]],gt])
								break
					elif nexthop[j+1] in hosts_list:
						for ht in exist_hosts :
							if ht[0] == nexthop[j+1] :
								links.append([[nexthop[j],"unknown",nexthop[j+1]],ht])
								break
					else :
						links.append([[nexthop[j],"unknown",nexthop[j+1]],[nexthop[j+1],"unknown"]])
					j+=1
	
	print links
	#try:
		
	driver = GraphDatabase.driver("bolt://localhost", auth=basic_auth("neo4j", "azerty159"))
	session = driver.session()	
	#session.run(constraint_query)
	#session.run(constraint_query1)		
	#session.run(insert_query, parameters={"sources": sr, "destination" :dst })
	session.run(insert_query1, parameters={"links": links})
	session.close()
	print "fffjjjhhh"
	#except :
			#pass					
	
	return 0

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
