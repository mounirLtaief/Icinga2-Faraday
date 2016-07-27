#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  Retreive_from_couchdb.py
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


import httplib, json
import simplejson
import couchdb


class Couch:

	def __init__(self, host, port=5984, options=None):
		self.host = host
		self.port = port

	def connect(self):
		return httplib.HTTPConnection(self.host, self.port) # No close()


     
	def listHt(self,dbName):
		c = self.connect()
		"""List all hosts in a given database"""
		
		#r = self.get(''.join(['/', dbName, '/', '_design/hosts/_view/hosts']))
		r = self.get(''.join(['/', dbName, '/', '_design/interfaces/_view/interfaces']))
		#r = simplejson.dumps(json.loads(r.read()), sort_keys=True, indent=4)
		#r = simplejson.dumps(json.loads(r.read()))
		return r
		#prettyPrint(r)

	def get(self, uri):
		c = self.connect()
		headers = {"Accept": "application/json"}
		c.request("GET", uri, None, headers)
		return c.getresponse()

	def post(self, uri, body):
		c = self.connect()
		headers = {"Content-type": "application/json"}
		c.request('POST', uri, body, headers)
		return c.getresponse()

	def put(self, uri, body):
		c = self.connect()
		if len(body) > 0:
			headers = {"Content-type": "application/json"}
			c.request("PUT", uri, body, headers)
		else:
			c.request("PUT", uri, body)
			return c.getresponse()

	def delete(self, uri):
		c = self.connect()
		c.request("DELETE", uri)
		return c.getresponse()
	
	
def hosts_list(host,port,dbname):
	
   	server = Couch(host,port)
    
	Hostslist=server.listHt(dbname)
  
	Nodesp = json.loads(Hostslist.read())
	nodesinfo = Nodesp['rows']
	data=[]
	comp = 0
	max_it = Nodesp['total_rows']
	while comp < max_it :
		hostnames = nodesinfo[comp]['value']['hostnames']
		name =  nodesinfo[comp]['value']['name']
		ip = nodesinfo[comp]['value']['ipv4']['address']
		mac = nodesinfo[comp]['value']['mac']
		host_info= {
		'hostname' : hostnames,
		'address' : ip,
		'mac': mac
		}
		data.append(host_info)
		comp+=1
	data = json.dumps(data)
	return data

#def main(arg):
	#data1 = hosts_list('localhost','5984','scan-test123')
	#data1 = json.loads(data1)
	#print simplejson.dumps(data1, sort_keys=True, indent=4)
	#print data1[0]
	#print data1[0]['ip']
	#print data1[0]['hostname'][0]
	#return 0
#if __name__ == '__main__':
    #import sys
    #sys.exit(main(sys.argv))
