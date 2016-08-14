#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  topology.py
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
import json
from neo4j.v1 import GraphDatabase, basic_auth

def main(data,nodenb):
	driver = GraphDatabase.driver("bolt://localhost", auth=basic_auth("neo4j", "azerty159"))
	session = driver.session()
	
	data = json.loads(data)
	#N=nodenb
	#i=0
	#edgenb =0
	#L=len(data)
	##print len(data[i]['from'])
	#while i< L:
		#if len(data[i]['from'])> 1 :
			#edgenb+=len(data[i]['from'])
		#else:
			#edgenb+=len(data[i]['to'])
		#i+=1
	
	#print edgenb
	
	insert_query = '''
	
	UNWIND {links} AS link
	MERGE (h1:host {name: link[0]})
	MERGE (h2:nexthop {name: link[1]})
	MERGE (h1)-[:CONNECT_TO]->(h2);
	'''
	nodes=[]
	for node in data :
				if len(node['from'])> 1 :
					for j in range(len(node['from'])) :
						nodes.append([node['from'][j],node['to']])
				
				else :
					for j in range(len(node['to'])) :
						if j==0 :
							nodes.append([node['from'],node['to'][j]])
						if j < L :
							nodes.append([node['to'][j],node['to'][j+1]])
	session.run(insert_query, parameters={"links": nodes})	
	session.close()	
	return 0

#if __name__ == '__main__':
    #import sys
    #sys.exit(main(sys.argv))
