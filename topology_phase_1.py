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
from neo4j.v1 import GraphDatabase,basic_auth
from py2neo import Graph, Path,Node
# from py2neo import neo4j

if os.name != "nt":
    import fcntl
    import struct


    def get_interface_ip(ifname):
        s = socket.socket ( socket.AF_INET,socket.SOCK_DGRAM )
        ip = socket.inet_ntoa ( fcntl.ioctl ( s.fileno ( ),0x8915,struct.pack ( '256s',ifname[ :15 ] ) )[ 20:24 ] )
        return


def get_ipsource():
    ip = socket.gethostbyname ( socket.gethostname ( ) )
    if ip.startswith ( "127." ) and os.name != "nt":
        interfaces = {
            "eth0",
            "eth1",
            "eth2",
            "wlan0",
            "wlan1",
            "wifi0",
            "ath0",
            "ath1",
            "ppp0",
        }
        for ifname in interfaces:
            try:
                ip = get_interface_ip ( ifname )
                break
            except IOError:
                pass
    return ip


def verify_gate(hop,gateway,data,hopnbr):
    gate = None
    exist = False
    for hops in gateway:
        if hops[ 'address' ] == hop:
            gate = hops
            exist = True
            return exist,gate
    for nod in data:
        if nod[ 'address' ] == hop:
            gate = dict ( hostname=nod[ 'hostname' ],address=nod[ 'address' ],mac=nod[ 'mac' ],hop_nbr=hopnbr + 1 )
            exist = True
            return exist,gate
    return exist,gate


def verify_curr_host(address,data):
    host = None
    exist = False
    for nod in data:
        if nod[ 'address' ] == address:
            host = nod
            exist = True
            return exist,host

    return exist,host


def insert_host_to_db(host,dbname,password,data):
    services =[]
    i=0
    for serv in data['services']:
        service = [protocol :var = data[ 'services' ][ i ]['protocol'],description :var = data[ 'services' ][ i ]['description'],
        status :var = data[ 'services' ][ i ],ports :var = data[ 'services' ][ i ]['ports'],name :var = data[ 'services' ][ i ]['name']
        ]
    insert_query = '''
        UNWIND {data} AS data
        MERGE (h:host{name: data['host']['name'],description: data['host']['description'],os: data['host']['os'],
        hostname : data['interface']['hostnames'], interface_description :data['interface']['description'],
        address : data['interface']['address'],mac : data['interface']['mac'], networkseg : data['interface']['network_segment'],
        mask : data['interface']['mask'], gateway: data['interface']['gateway'],type : data['interface']['type']} );
        '''
    driver = GraphDatabase.driver ( host,auth=basic_auth ( dbname,password ) )
    session = driver.session ( )
    session.run ( insert_query,parameters={"data": data} )
    session.close ( )
    return 0


def search_query(host,dbname,password,data):
    match_query = '''
        UNWIND {data} AS data
        MATCH (h:host) WHERE h.name = data['host']['name'] return h ;
            '''
    driver = GraphDatabase.driver ( host,auth=basic_auth ( dbname,password ) )
    session = driver.session ( )
    result = session.run ( match_query,parameters={"data": data} )
    session.close ( )
    return result


def insert_data_to_db(host,dbname,password,data):
    insert_query = '''
        UNWIND {links} AS link
    	MERGE (h1:node_UP { name: link[0]['hostname'],address: link[0]['address'],mac: link[0]['mac'] })
    	MERGE (h2:node_UP { name: link[1]['hostname'], address: link[1]['address'],mac: link[1]['mac']  })
    	MERGE (h1)<-[:CONNECT_TO]->(h2);
    	'''
    driver = GraphDatabase.driver ( host,auth=basic_auth ( dbname,password ) )
    session = driver.session ( )
    session.run ( insert_query,parameters={"links": data} )
    session.close ( )


def traceRoute(data):
    ip = get_ipsource ( )
    gateway_0 = None
    curr_host = None
    # gateway_info = [ ]
    gateway = [ ]
    local_net = [ ]
    node_nbr = 0
    links = [ ]
    for node in data:
        dest_addr = node[ 'address' ]
        hops_info,hops_to = traceroute.TraceRoute ( dest_addr )
        l = len ( hops_to )
        # local network
        if l == 1:
            if hops_to[ 0 ] == ip:
                local_net.append ( node )
                if node[ 'address' ] == ip:
                    curr_host = node
            if hops_to[ 0 ] <> ip:
                gateway_0 = node
                gate_0 = dict ( hostname=node[ 'hostname' ],address=node[ 'address' ],mac=node[ 'mac' ],hop_nbr=l )
                gateway.append ( gate_0 )
                # distant networks
        if l > 1:
            hop_nbr = 0
            exist,gate = verify_gate ( hops_to[ 0 ],gateway,data,hop_nbr )

            exist_curr = curr_host is not None

            if not exist_curr:
                exist_curr,curr_host = verify_curr_host ( ip,data )
            if not exist_curr:
                host_info = dict ( hostname="localhost",address=ip,mac="x.x.x.x" )
            if exist_curr and exist:
                links.append ( [ curr_host,gate ] )
            if exist_curr and not exist:
                links.append ( [ curr_host,hops_info[ 0 ] ] )
                gateway.append ( hops_info[ 0 ] )
            if not exist_curr and exist:
                links.append ( [ host_info,gate ] )
            if not exist_curr and not exist:
                links.append ( [ host_info,hops_info[ 0 ] ] )
                gateway.append ( hops_info[ 0 ] )

            while hop_nbr < l - 1:

                exist,gate = verify_gate ( hops_to[ hop_nbr + 1 ],gateway,data,hop_nbr )
                if exist:
                    links.append ( [ links[ len ( links ) - 1 ][ 1 ],gate ] )
                if not exist:
                    links.append ( [ links[ len ( links ) - 1 ][ 1 ],hops_info[ hop_nbr + 1 ] ] )
                    gateway.append ( hops_info[ hop_nbr + 1 ] )
                hop_nbr += 1

            # if hops_info[ l - 1 ][ 'address' ] <> node[ 'address' ]:
            #     unknown_net = dict ( hostname="unknown network",address="unreachable",mac="",hop_nbr=l + 1 )
            #     links.append ( [ links[ len ( links ) - 1 ][ 1 ],unknown_net ] )
            #     links.append ( [ unknown_net,node ] )
        node_nbr += 1
    # local network
    for host in local_net:
        links.append ( [ host,gateway_0 ] )

    return links


def get_topology_links():
    data = Retreive_from_couchdb.hosts_list ( 'localhost','5984','scan-test123' )
    data = json.loads ( data )
    links = traceRoute(data)
    insert_data_to_db('bolt://localhost','neo4j','azerty159',links)

    return 0


def main(args):
    # get_topology_links ( )
    data = Retreive_from_couchdb.get_hosts_info('localhost','5984','scan-test123')
    # print data[1]
    # print data[1]['host']
    # data = json.loads ( data )
    d0 = data.pop(0)
    for row in data :
        insert_host_to_db('bolt://localhost','neo4j','azerty159',row)
    # insert_host_to_db('bolt://localhost','neo4j','azerty159',data[1])
    # result = search_query('bolt://localhost','neo4j','azerty159',data[1])
    # for record in result:
    #     print record["h"]
    #     r =record["h"]["host"]
    # print r
    # k= str(r).split()
    # print k[0]


    # graph_db = Graph("http://neo4j:azerty159@localhost:7474/db/data/")
    # alice, = graph_db.create ( {"name": "Alice"} )
    return 0


if __name__ == '__main__':
    import sys
    sys.exit ( main ( sys.argv ) )
