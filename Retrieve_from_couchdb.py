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


import httplib,json
import simplejson
import couchdb

class Couch:
    def __init__(self,host,port=5984,options=None):
        self.host = host
        self.port = port

    def connect(self):
        return httplib.HTTPConnection ( self.host,self.port )  # No close()

    def get_hosts_info(self,dbName):
        c = self.connect ( )
        """List all hosts in a given database"""
        r = self.get ( ''.join ( [ '/',dbName,'/','_design/hosts/_view/hosts' ] ) )
        return r

    def get_hosts_if(self,dbName):
        c = self.connect ( )
        """List all hosts'interfaces in a given database"""
        r = self.get ( ''.join ( [ '/',dbName,'/','_design/interfaces/_view/interfaces' ] ) )
        return r

    def get_hosts_services(self,dbName):
        c = self.connect ( )
        """List all hosts'services in a given database"""
        r = self.get ( ''.join ( [ '/',dbName,'/','_design/services/_view/byhost' ] ) )
        return r

    def get_hosts_vul(self,dbName):
        c = self.connect ( )
        """List all hosts'vulnurabilties in a given database"""
        r = self.get ( ''.join ( [ '/',dbName,'/','_design/vulns/_view/all' ] ) )
        return r

    def get(self,uri):
        c = self.connect ( )
        headers = {"Accept": "application/json"}
        c.request ( "GET",uri,None,headers )
        return c.getresponse ( )

    def post(self,uri,body):
        c = self.connect ( )
        headers = {"Content-type": "application/json"}
        c.request ( 'POST',uri,body,headers )
        return c.getresponse ( )

    def put(self,uri,body):
        c = self.connect ( )
        if len ( body ) > 0:
            headers = {"Content-type": "application/json"}
            c.request ( "PUT",uri,body,headers )
        else:
            c.request ( "PUT",uri,body )
            return c.getresponse ( )

    def delete(self,uri):
        c = self.connect ( )
        c.request ( "DELETE",uri )
        return c.getresponse ( )


def load_data(host,port,dbname):
    server = Couch ( host,port )
    hosts_List = json.loads ( server.get_hosts_info ( dbname ).read ( ) )
    hosts_Interfaces = json.loads ( server.get_hosts_if ( dbname ).read ( ) )
    hosts_Services = json.loads ( server.get_hosts_services ( dbname ).read ( ) )
    hosts_vul = json.loads ( server.get_hosts_vul ( dbname ).read ( ) )

    return hosts_List,hosts_Interfaces,hosts_Services,hosts_vul


def get_host_info(host):
    name = host[ 'value' ][ 'name' ]
    desc = host[ 'value' ][ 'description' ]
    os = host[ 'value' ][ 'os' ]
    return dict ( name=name,description=desc,os=os )


def get_if_Info(key,interface):
    for row in interface:
        if row[ 'key' ] == key:
            hostnames = row[ 'value' ][ 'hostnames' ]
            address = row[ 'value' ][ 'ipv4' ][ 'address' ]
            mask = row[ 'value' ][ 'ipv4' ][ 'mask' ]
            gateway = row[ 'value' ][ 'ipv4' ][ 'gateway' ]
            network_segment = row[ 'value' ][ 'network_segment' ]
            mac = str(row[ 'value' ][ 'mac' ]).replace(':','')
            mac ='0x'+mac
            mac = str(mac).lower()
            type = row[ 'value' ][ 'type' ]
            description = row[ 'value' ][ 'description' ]
            return dict ( hostnames=hostnames,description=description,mac=mac,type=type,address=address,
                          network_segment=network_segment,mask=mask,gateway=gateway )
    return {}


def get_serv_info(key,serv):
    services = []

    for row in serv:
        if row['key'] == key:
            name = row[ 'value' ]['name']
            desc = row[ 'value' ]['description']
            protocol = row[ 'value' ]['protocol']
            ports = row[ 'value' ]['ports']
            status = row[ 'value' ]['status']
            services.append(dict(name = name,description = desc,protocol = protocol, ports = ports, status= status))

    return services


def get_vul_info(key,vuls):
    vuls_host = []

    for row in vuls:
        if row['key'].split(".")[0]==key:
            name = row[ 'value' ]['name']
            desc = row[ 'value' ][ 'desc' ]
            type = row[ 'value' ][ 'type' ]
            severity = row[ 'value' ][ 'severity' ]
            resolution = row[ 'value' ][ 'resolution' ]
            impact = row[ 'value' ][ 'impact' ]
            if type == 'VulnerabilityWeb':
                website = row[ 'value' ][ 'website' ]
                method = row[ 'value' ][ 'method' ]
                params = row[ 'value' ][ 'params' ]
                path = row[ 'value' ][ 'path' ]
                pname = row[ 'value' ][ 'pname' ]
                query = row[ 'value' ][ 'query' ]
                request = row[ 'value' ][ 'request' ]
                response = row[ 'value' ][ 'response' ]
                vuls_host.append( dict(name=name,desc=desc,resolution= resolution,severity=severity,type=type,
                                  impact=impact,method=method,params=params,path=path,pname=pname,
                                  query=query,request=request,response=response,website = website ))
            else :
                vuls_host.append (dict( name=name,desc=desc,resolution=resolution,severity=severity,type=type,impact=impact))
    return vuls_host


def get_hosts_info(cred):
    data = load_data (cred[0],cred[1],cred[2])
    # hosts = [ dict ( number=data[ 0 ][ 'total_rows' ] ) ]
    hosts = []
    for row in data[ 0 ][ 'rows' ]:
        key = row[ 'key' ]
        host_info = get_host_info ( row )
        if_Info = get_if_Info ( key,data[ 1 ][ 'rows' ] )
        services_info = get_serv_info ( key,data[ 2 ][ 'rows' ] )
        vul_info = get_vul_info ( key,data[ 3 ][ 'rows' ] )
        hosts.append ( dict ( host=host_info,interface=if_Info,services=services_info,vuls=vul_info ) )

    return hosts


    # nodesinfo = Nodesp[ 'rows' ]
    # data = [ ]
    # comp = 0
    # max_it = Nodesp[ 'total_rows' ]
    # while comp < max_it:
    #     hostnames = nodesinfo[ comp ][ 'value' ][ 'hostnames' ]
    #     name = nodesinfo[ comp ][ 'value' ][ 'name' ]
    #     ip = nodesinfo[ comp ][ 'value' ][ 'ipv4' ][ 'address' ]
    #     mac = nodesinfo[ comp ][ 'value' ][ 'mac' ]
    #     host_info = {
    #         'hostname': hostnames,
    #         'address': ip,
    #         'mac': mac
    #     }
    #     data.append ( host_info )
    #     comp += 1
    # data = json.dumps ( data )
    # return data


# def main(arg):
#     data = get_hosts_info('localhost','5984','scan-test123')
#     services = [ ]
#     i=0
#     for serv in data[2]['services']:
#         # print serv[i]
#         services.append ([ serv[ 'protocol' ],serv['decription' ],serv['status'],serv[ 'ports' ], serv['name' ]])
#         i+=1
#
#     print services
#     # d0 = data.pop(0)
#     # print d0
#     # print json.dumps(data)
#     data1 = json.loads(data1)
#     # print simplejson.dumps(data1, sort_keys=True, indent=4)
#     # print data1[0]
#     # print data1[0]['ip']
#     # print data1[0]['hostname'][0]
#     return 0
#
# if __name__ == '__main__':
#     import sys
# sys.exit(main(sys.argv))
