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
				if route[j] == ip:
					return True
				j+=1	
	return False

def main(args):
	
	'''
    First stage : traceroute 	
	'''
	data,gatewaylist,hostsnb = plugin.hosts_dis('localhost','5984','scan3')
	#print gatewaylist
	#data = plugin.hosts_dis('localhost','5984','scan4')
	#print simplejson.dumps(data, sort_keys=True, indent=4)
	hopslist = []
	data1 = json.loads(data)
	
	
	
	#print simplejson.dumps(data1, sort_keys=True, indent=4)
	#print data1[0]
	
	constraint_query = '''
	create constraint on (h:`host`) assert h.`name` is unique;
	'''
	constraint_query1 = '''
	create constraint on (g:`gateway`) assert g.`name` is unique;
	'''
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
	#print len(data1)
	#print len(data1)
	#print len(data1[0])
	#for z in data1 :
		#print z
		#print "hhhh"
	#print data1
	
	#for host in data1:
		#p=1
		#gate = []
		#while p< len(host) :
			#if host[p]['ip'] == host[p]['gateway'] :
				#gate.append([host[p]['ip'],host[p]['os']])
				
				#print "yes"
				
			#p+=1
	#print "hhhhhh"
	#print gate
	routes = []
	for route in gatewaylist:
			routelist = []
			routelist = traceroute._traceroute(route)
			if len(routelist)>0 :
				routes.append(routelist)	
	#print routes
	#print routes[0]
	#print routes[1][1]
	#sr =[]	
	#dst = []
	exist_hosts = []
	hosts_list = []
	links = []	
	gate = []
	nd = []
	ip = _verify_ipsource()
	gate_comp = 0
	for node in data1 :
		k = len(node)
		g=1
		while g < k:
			if _verifyip(node[g]['ip'],routes) and node[g]['ip'] <> node[g]['gateway'] :
				exist_hosts.append([node[g]['ip'],node[g]['os'],node[g]['gateway']])
				hosts_list.append(node[g]['ip'])	
			if node[g]['ip'] == node[g]['gateway'] :
				gate.append([node[g]['ip'],node[g]['os']])
				gate_comp +=1 
			g+=1
		i=1
		while i < k :
			if node[i]['ip'] <> node[i]['gateway'] :
				if node[i]['ip'] == ip :
					nd = [node[i]['ip'],node[i]['os'],node[i]['gateway']]
				else :
					links.append([[node[i]['ip'],node[i]['os'],node[i]['gateway']],gate])
				#sr.append([data1[0][i]['ip'],data1[0][i]['os'],data1[0][i]['gateway']])
			#else :
				#dst.append([data1[0][i]['ip'],data1[0][i]['os']])
			i+=1
		#if not exist:
		#hops = traceroute._traceroute(gatewaylist[0])
		if len(routes)>0 :
			for nexthop in routes:
				if len(nd)>0 :
					if nexthop[0] in gatewaylist :
						for gt in gate :
							if gt[0] == nexthop[0] :
								links.append([nd,gt])
								break
					else :
						links.append([nd,[nexthop[0],"UNKNOWN"]])	
				else :
					if nexthop[0] in gatewaylist :
						for gt in gate :
							if gt[0] == nexthop[0] :
								links.append([[ip,"UNKNOWN",nexthop[0]],gt])
								break
					else:
						links.append([[ip,"UNKNOWN",nexthop[0]],[nexthop[0],"UNKNOWN"]])
				#sr.append([ip,"unkown",hops[0]])
			#links.append([[ip,"unkown",hops[0]],[hops[0],"unkown"]])
				l = len(nexthop)
				if l > 1 :				
					j=0
					while j < l-1:
					#dst.append([hops[j],"unkown"])
					#sr.append([hops[j],"unkown",hops[j+1]])
						if nexthop[j+1] in gatewaylist :
							for gt in gate :
								if gt[0] == nexthop[j] :
									links.append([nexthop[j],"unkown",nexthop[j+1]],gt])
									break
						else if nexthop[j+1] in hosts_list:
							for ht in exist_hosts :
								if ht[0] == nexthop[j+1] :
									links.append([[nexthop[j],"unkown",nexthop[j+1]],ht])
									break
						else :
							links.append([[nexthop[j],"unkown",nexthop[j+1]],[nexthop[j+1],"unkown"]])
						
						#if nexthop[j] in gatewaylist and nexthop[j+1] not in gatewaylist :
							#for gt in exist_hosts :
								#if gt[0] == nexthop[j] :
									#links.append([gt,[nexthop[j+1],"unkown"]])
									#break
						#if nexthop[j] not in gatewaylist and nexthop[j] in gatewaylist :
							#for gt in exist_hosts :
								#if gt[0] == nexthop[j+1] :
									#links.append([[nexthop[j],"unkown",nexthop[j+1]],gt])
									#break
						#gtway = []
						#ordre = 0
						#if 	nexthop[j] in gatewaylist and nexthop[j] in gatewaylist :
							#for gt in exist_hosts :
								#if gt[0] == nexthop[j] :
									#gtway.append(gt)
								#if gt[0] == nexthop[j+1] :
									#gtway.append(gt)
									#ordre = 1
								#if len(gtway) == 2 :
									#break
							#if ordre ==0 :
								#links.append([gtway[0],gtway[1]])
							#else :
								#links.append([gtway[0],gtway[1]])
						
						
						
						
						#if nexthop[j] in hosts_list and nexthop[j+1] not in hosts_list :
							#for gt in gate :
								#if gt[0] == nexthop[j] :
									#links.append([gt,[nexthop[j+1],"unkown"]])
									#break
						#if nexthop[j] not in hosts_list and nexthop[j] in hosts_list :
							#for gt in gate :
								#if gt[0] == nexthop[j+1] :
									#links.append([[nexthop[j],"unkown",nexthop[j+1]],gt])
									#break
						#gtway = []
						#ordre = 0
						#if 	nexthop[j] in hosts_list and nexthop[j] in hosts_list :
							#for gt in gate :
								#if gt[0] == nexthop[j] :
									#gtway.append(gt)
								#if gt[0] == nexthop[j+1] :
									#gtway.append(gt)
									#ordre = 1
								#if len(gtway) == 2 :
									#break
							#if ordre ==0 :
								#links.append([gtway[0],gtway[1]])
							#else :
								#links.append([gtway[0],gtway[1]])
						j+=1
				#dst.append([hops[j],"unkown"])
				#if hops[j]<> 
				#links.append([[hops[j],"unkown",gatewaylist[0]],[gatewaylist[0],"unkown"]])
	
	print links
	driver = GraphDatabase.driver("bolt://localhost", auth=basic_auth("neo4j", "azerty159"))
	session = driver.session()	
	session.run(constraint_query)
	session.run(constraint_query1)		
	#session.run(insert_query, parameters={"sources": sr, "destination" :dst })
	session.run(insert_query1, parameters={"links": links})
	session.close()			
	
	
	#if len(gatewaylist) > 1 :
		#compt = 0
		#for i in gatewaylist :
			#exist, ip = _verify_ipsource(data1[0])
			#k = len(data1[compt])
			#i=1
			#while i < k :
				#g=1
				#gate = []
				#while g < k:
					#if data1[0][g]['ip'] == data1[0][0]['gateway'] :
						#gate = [data1[0][g]['ip'],data1[0][g]['os']]
					#g+=1
			#if data1[0][i]['ip'] <> data1[0][0]['gateway'] :
				#links.append([[data1[0][i]['ip'],data1[0][i]['os'],data1[0][i]['gateway']],gate])
				##sr.append([data1[0][i]['ip'],data1[0][i]['os'],data1[0][i]['gateway']])
			##else :
				##dst.append([data1[0][i]['ip'],data1[0][i]['os']])
			#i+=1
			#compt+=1
		
		
	#hostsnb = len(gatewaylist)
	#print hostsnb
	#print gatewaylist[0]
	#count = True 
	#if len(gatewaylist) == 1 :
		#item = {}
		#item1 = {}
		#exist, ip = _verify_ipsource(data1[0])
		#if exist:
			#item["from"] = _hostslist(data1[0],gatewaylist[0])
			#item["to"] = gatewaylist[0]	
		#else :
			#item["from"] = _hostslist(data1[0],gatewaylist[0])
			#item["to"] = gatewaylist[0]	
			#item1["from"] = ip
			#item1["to"] = traceroute._traceroute(gatewaylist[0])
			#if count:
				#hostsnb+=1
				#count = False 
		#hopslist.append(item)
		#if len(item1) > 0 :
			#hopslist.append(item1)
	
	#if len(gatewaylist) > 1 :
		#compt = 0
		#for i in gatewaylist :
			#item = {}
			#item1 = {}
			#exist, ip = _verify_ipsource(data1[compt])
			#if exist:
				#item["from"] = _hostslist(data1[compt],gatewaylist[compt])
				#item["to"] = gatewaylist[compt]	
			#else :
				#item["from"] = _hostslist(data1[compt],gatewaylist[compt])
				#item["to"] = gatewaylist[compt]	
				#item1["from"] = ip
				#item1["to"] = traceroute._traceroute(gatewaylist[compt])
				#if count:
					#hostsnb+=1
					#count = False 
			#hopslist.append(item)
			#hopslist.append(item1)
			#compt+=1
		
	
	##print hostsnb
	#hopslist = json.dumps(hopslist)
	##print simplejson.dumps(json.loads(hopslist), sort_keys=True, indent=4)
	##list1 = json.loads(hopslist)
	##print len(list1)
	##print len(hopslist[0]['from'])
	##topology_graph.main(hopslist,hostsnb)
	#topology.main(hopslist,hostsnb)
		
		
	#print hopslist
	#print data1[0]
	#if '192.168.178.229'in data1[0]:
		#print "yes yes"
	#if len(gatewaylist) > 1:
		#hopslist = []
		#for i in gatewaylist:
			#hops = _traceroute(i)
			#hopslist.append(hops)
	
	#print data1
	#indice = 0 
	#for i in gatewaylist :
		#print i
		
	#hosts = data1[0]
	#print hosts['gateway']
	#for i in hosts:
		#print i
	
	#print data1[0]['gateway']
	
	#print "list of host: %s" %hostslist[0:len(hostslist)]
	
	#hopslist = traceroute.tracrout(hostslist[1])
	#if len(hopslist)== 0:
		#print "no route for this host"
	 
	##hopslist = traceroute.tracrout('172.217.19.110')
	#else :
		#print "\nlist of hops :%s " %hopslist[0:len(hopslist)]
	##print "\nlist of hops :%s " %hopslist[0:len(hopslist)]
	
	return 0

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
