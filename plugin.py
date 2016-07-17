#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  untitled.py
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

def prettyPrint(s):
    """Prettyprints the json response of an HTTPResponse object"""

    #HTTPResponse instance -> Python object -> str
    print simplejson.dumps(json.loads(s.read()), sort_keys=True, indent=4)

class Couch:

	def __init__(self, host, port=5984, options=None):
		self.host = host
		self.port = port

	def connect(self):
		return httplib.HTTPConnection(self.host, self.port) # No close()


     
	def listHt(self,dbName):
		c = self.connect()
		"""List all hosts in a given database"""
		
		r = self.get(''.join(['/', dbName, '/', '_design/hosts/_view/hosts']))
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
	
	
def hosts_dis(host,port,dbname):
	
    #server = Couch('localhost', '5984')
    server = Couch(host,port)
    
    Hostslist=server.listHt(dbname)
    #Nodesp = simplejson.dumps(json.loads(Hostslist.read()))
    Nodesp = json.loads(Hostslist.read())
    #print Nodesp[1]
    nodesinfo = Nodesp['rows']
    nbrhosts = 0
    #print nodesinfo[0]['value']['default_gateway'][0]
    #print "\nList hosts discovered by scan:"
    #print nodesinfo[nbrhosts]['value']['os']
    hostlist = []
    for i in nodesinfo:
		hostip = nodesinfo[nbrhosts]['value']['name']
		gateway = nodesinfo[nbrhosts]['value']['default_gateway'][0]
		os = nodesinfo[nbrhosts]['value']['os']
		hostlist.append(hostip)
		nbrhosts+=1
		#print "Host IP address: %s" %hostip +"------> gateway: %s" %gateway +" os : %s " %os
    #print "\nNomber of hosts discovered by scan: %s" %nbrhosts
    
    #print "hosts list : %s" %str(hostlist[0:len(hostlist)])
    #if '133.231.245.163' in hostlist :
		#print "YES"
    return hostlist

#if __name__ == '__main__':
    #import sys
    #sys.exit(main(sys.argv))
