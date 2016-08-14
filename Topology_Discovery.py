#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  topology_phase_2.py
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
import sys
import Store_to_Neo4jDB as storeData
import ifType as type
import Retrieve_from_couchdb as RetrieveData
import DatabaseAuth as db_auth
from pysnmp.entity.rfc3413.oneliner import cmdgen
from neo4j.v1 import GraphDatabase,basic_auth
import ast

class SnmpSession(object):
    """SNMP Session object"""

    def __init__(self):
        self.host = "localhost"
        self.port = 161
        self.community = "public"
        self.version = "2c"

    def get_config(self):
        if self.version == "1":
            return cmdgen.CommunityData('test-agent', self.community, 0),

        elif self.version == "2c":
            return cmdgen.CommunityData('test-agent', self.community)

        elif self.version == "3":
            return cmdgen.UsmUserData('test-user', 'authkey1', 'privkey1'),

    def oidstr_to_tuple(self, s):
        """ FIXME remove trailing dot if there is one"""

        return tuple([int(n) for n in s.split(".")])

    def snmp_get(self, oid):
        r = ()

        oid = self.oidstr_to_tuple(oid)

        snmp_config = self.get_config()

        errorIndication, errorStatus, \
        errorIndex, varBinds = cmdgen.CommandGenerator().getCmd(
            snmp_config, cmdgen.UdpTransportTarget((self.host, self.port)), oid)

        if errorIndication:
            print errorIndication
            # print "hhhh"
            print errorStatus
            print errorIndex
        else:
            if errorStatus:
                print '%s at %s\n' % (
                    errorStatus.prettyPrint(), varBinds[int(errorIndex) - 1])
                # print "cccggg"
            else:
                for name, val in varBinds:
                    return (name.prettyPrint(), val.prettyPrint())

    def snmp_getnext(self, oid):
        # type: (object) -> object
        # type: (object) -> object
        r = []

        oid = self.oidstr_to_tuple(oid)
        snmp_config = self.get_config()

        errorIndication, errorStatus, errorIndex, \
        varBindTable = cmdgen.CommandGenerator().nextCmd(
            snmp_config, cmdgen.UdpTransportTarget((self.host, self.port)), oid)

        if errorIndication:
            print errorIndication
            print errorStatus
            print errorIndex
            # print "hhhh"
        else:
            if errorStatus:
                # print "dfhjdhfj"
                print '%s at %s\n' % (
                    errorStatus.prettyPrint(), varBindTable[-1][int(errorIndex) - 1])
            else:
                for varBindTableRow in varBindTable:
                    for name, val in varBindTableRow:
                        r.append((name.prettyPrint(), val.prettyPrint()))

        return r


def snmp_devices_discovery(hop):

    dev = [ ]
    snmp = SnmpSession()
    snmp.host = hop[0]
    sys_Desc = snmp.snmp_getnext ( type.OID_sysDescription )
    if sys_Desc == []:
        return False, None,None
    else :
        dev_info = snmp_info(hop[0])
        for neigh in dev_info['neighbours']:
            dev.append((neigh['ipaddress'],neigh['mac']))

        for route in dev_info['nextRoute']:
            if route_not_exist(route ['next_route'],dev):
                dev.append((route ['next_route'],'0x000000000000'))
        return True, dev,dev_info

    return False, None,None


def route_not_exist(route,dev):
    for d in dev:
        if d[0]== route:
            return False

    return True


def verify_devices(dev, vis_dev, rest_dev):
    while dev != []:
        d = dev.pop()
        if d not in vis_dev:
            rest_dev.append(d)

    return rest_dev


def device_discovery(hosts):
    visited_devices = []
    snmp_dev_info = []
    dev_nn_snmp = []
    while hosts != []:
        h = hosts.pop()
        if h not in visited_devices:
            visited_devices.append(h)
            snmp_is_available, dev,dev_info = snmp_devices_discovery(h)
            if snmp_is_available:
                snmp_dev_info.append(dev_info)
                hosts = verify_devices(dev, visited_devices, hosts)
            else:
                dev_nn_snmp.append(h)
            # print hosts

    return [visited_devices,snmp_dev_info,dev_nn_snmp]


def get_SysType(num,mib_Bridge,mib_Printer):

    binary_Rep = "{0:b}".format(int(num[0][1]))
    # print binary_Rep
    if binary_Rep[5] == '0' :
        if binary_Rep[4] == '0':
            if mib_Printer == [] :
                return "Host"
            else :
                return "Printer"
        else :
            if binary_Rep[3]=='0':
                if binary_Rep[0] == '0':
                    return "Router"
                else :
                    return "L7 appilcation switch or Router"
            else:
                return "L4 switch"
    elif binary_Rep[4]=='0' :
        if mib_Bridge == []:
            return  "Host"
        else:
            return "L2 Switch"
    else:
        if mib_Bridge == []:
            if binary_Rep[0]=='0':
                return "Router"
            else :
                return "L7 application Switch or router"
        else :
            return "L3 switch with B Mib"

    return "unknown"


def get_ifstate(type_Num):

    if type_Num == '1':
        return "UP"
    elif type_Num == '2':
        return "DOWN"
    else:
        return "TESTING"

    return "unknown"


def get_ifnet(if_add,if_Index,net_Index):
    i=0
    for if_net in net_Index:
        if if_net[1]== if_Index:
            return if_add[i][1]
        i+=1
    return 'x.x.x.x'


def get_addtype(add_Index):
    if add_Index == '4':
        return "static"
    if add_Index =='3':
        return "dynamic"
    if add_Index == '2':
        return "invalid"
    if add_Index == '1':
        return "other"
    return "unknown"


def snmp_info(dev):

    snmp = SnmpSession()
    snmp.host = dev

    # Bridge Mib info
    mib_Bridge = snmp.snmp_getnext(type.OID_BridgeMib)
    mib_Printer = snmp.snmp_getnext(type.OID_PrinterMIB)

    # system info
    sys_Name = snmp.snmp_getnext(type.OID_sysName)
    sys_Desc = snmp.snmp_getnext(type.OID_sysDescription)
    sys_TypeNum = snmp.snmp_getnext(type.OID_sysServices)
    system_info = dict(name=sys_Name[0][1],description = sys_Desc[0][1],
                       type = get_SysType(sys_TypeNum,mib_Bridge,mib_Printer))

    # interfaces info
    if_Index = snmp.snmp_getnext(type.OID_ifIndex)
    if_Number = snmp.snmp_getnext(type.OID_ifNumber)
    if_Address = snmp.snmp_getnext(type.OID_ifPhysAddress)
    if_Name = snmp.snmp_getnext(type.OID_ifDescr )
    if_Type = snmp.snmp_getnext(type.OID_ifType)
    if_Astate = snmp.snmp_getnext(type.OID_ifAdminStatus)
    if_Operate = snmp.snmp_getnext(type.OID_ifOperStatus)

    # interfaces ip address info
    if_IpIndex = snmp.snmp_getnext(type.OID_ipAdEntIfIndex)
    if_IpAdd = snmp.snmp_getnext(type.OID_ipAdEntAddr)
    if_AddMask = snmp.snmp_getnext(type.OID_ipAdEntNetMask)
    if_Info= []
    for ifNum in range(int(if_Number[0][1])):
        ifInfo = dict(index=if_Index[ ifNum ][ 1 ],name=if_Name[ ifNum ][ 1 ],
                      mac=if_Address[ ifNum ][ 1 ],type=type.IFTYPES.get(int(if_Type[ifNum][1]),'UNKNOWN'),
                      adminstate=get_ifstate ( if_Astate[ ifNum ][ 1 ] ),
                      operationstate=get_ifstate ( if_Operate[ ifNum ][ 1 ] ),
                      ipaddress=get_ifnet ( if_IpAdd,if_Index[ ifNum ][ 1 ],if_IpIndex ),
                      mask =get_ifnet ( if_AddMask,if_Index[ ifNum ][ 1 ],if_IpIndex ))
        if_Info.append(ifInfo)

    # Arp cache info
    arp_Index = snmp.snmp_getnext(type.OID_ipNetToMediaIfIndex)
    arp_Ip = snmp.snmp_getnext(type.OID_ipNetToMediaNetAddress)
    arp_Ips = snmp.snmp_getnext(type.OID_ipNetToMediaPhysAddress)
    arp_AddType = snmp.snmp_getnext(type.OID_ipNetToMediaType)

    neighbours = []
    l = len(arp_Index)
    for neighbour in range(l):
        neighb = dict(ifname = if_Name[ int ( arp_Index[ neighbour ][ 1 ] ) - 1 ][ 1 ] ,
                      ipaddress = arp_Ip[ neighbour ][ 1 ] ,mac = arp_Ips[ neighbour ][ 1 ] ,
                      type = get_addtype ( arp_AddType[ neighbour ][ 1 ] ) )
        neighbours.append(neighb)

    # next ip route info
    route_Index = snmp.snmp_getnext(type.OID_ipRouteIfIndex)
    route_Next = snmp.snmp_getnext(type.OID_ipRouteNextHop)
    route_Mask = snmp.snmp_getnext(type.OID_ipRouteMask)
    route_Type = snmp.snmp_getnext(type.OID_ipRouteType)
    route_protocol = snmp.snmp_getnext(type.OID_ipRouteProto)

    next_net = []
    l1 = len(route_Index)
    for hop in range(l1):
        if route_Type[hop][1]=='4':
            next_hop = dict(if_next=if_Name[int(route_Index[hop][1]) - 1][1], next_route=route_Next[hop][1],
                            protocol=type.PROTOTYPES.get(int(route_protocol[hop][1]),'UNKNOWN'))
            next_net.append(next_hop)

    return dict(system=system_info,interfaces=if_Info,neighbours=neighbours,nextRoute =next_net)


def get_switchs_routers_hosts(devices):

    hosts = []
    switchs_routers = []

    for dev in devices:
        if dev['system']['type']=='Host' or dev['system']['type']=='Printer':
            hosts.append(dev)
        else:
            switchs_routers.append(switchs_routers)

    return [switchs_routers,hosts]


def next_interface_connect(ip,mac,devices_snmp,devices_non_snmp):
    for dev in devices_snmp:
        for interface in dev['interfaces']:
            for ifi in interface:
                if(ifi['mac']== mac and ifi['ipaddress'] == ip ):
                    return dev,ifi['name']

    for dev in devices_non_snmp:
        if dev[0] == ip and dev[1] == mac:
                return dev,None
        if dev[0] == ip and dev[1] != mac:
            if dev[1] == '0x000000000000' and mac != '0x000000000000':
                dev[1] = mac
                return dev,None
            if dev[1]!= '0x000000000000' and mac == '0x000000000000':
                return dev,None

    return None,None


def exist_in_neighbour(nextroute,interfaces):

    for interface in interfaces:
        if interface['ipaddress']== nextroute:
            return True

    return False


def get_l2l3_connectivity(cred,dev,devices_snmp,devices_non_snmp):
    #neighbour relations
    for neighbour in dev['neighbours']:
        next_neigh,next_neigh_if= next_interface_connect(neighbour['ipaddress'],neighbour['mac'],devices_snmp,devices_non_snmp)
        if next_neigh != None:
            storeData.store_connectivity (cred,dev,neighbour[ 'ifname' ],next_neigh,next_neigh_if )

    #next route relations
    for nextroute in dev['nextRoute']:
        if not exist_in_neighbour(nextroute['next_route'],dev['neighbours']):
            next_neigh,next_neigh_if = next_interface_connect ( nextroute[ 'next_route' ],'0x000000000000',devices_snmp,devices_non_snmp )
            if next_neigh != None:
                storeData.store_connectivity (cred,dev,nextroute[ 'if_next' ],next_neigh,next_neigh_if )

    return 0


def l2_l3_connectivity (cred,l2_l3_dev,dev_non_snmp):
    # print l2_l3_dev
    i=0
    while i<len(l2_l3_dev):
        dev = l2_l3_dev.pop(i)
        get_l2l3_connectivity(cred,dev,l2_l3_dev,dev_non_snmp)
        l2_l3_dev.insert(i,dev)
        i+=1
    return 0


def get_host_l2l3_connectivity(cred,host,l2l3,nn_snmp,hosts):
    # print host
    #neighbour switchs routers
    nn_vis_neighbour = []
    nn_vis_router = []
    for neighbour in host['neighbours']:
        next_neigh,next_neigh_if = next_interface_connect (neighbour[ 'ipaddress' ],neighbour[ 'mac' ],l2l3,nn_snmp )
        if next_neigh != None:
            storeData.store_connectivity (cred,host,neighbour[ 'ifname' ],next_neigh,next_neigh_if )
        else:
            nn_vis_neighbour.append(neighbour)

    # next route relations nextRoute
    for nextroute in host[ 'nextRoute' ]:
        if not exist_in_neighbour ( nextroute[ 'next_route' ],host[ 'neighbours' ] ):
            next_neigh,next_neigh_if = next_interface_connect ( nextroute[ 'next_route' ],'0x000000000000',l2l3,nn_snmp )
            if next_neigh != None:
                storeData.store_connectivity (cred, host,nextroute[ 'if_next' ],next_neigh,next_neigh_if )
            else:
                nn_vis_router.append(nextroute)

    for neighbour in nn_vis_neighbour:
        next_neigh,next_neigh_if = next_host_neighbour(neighbour[ 'ipaddress' ],neighbour[ 'mac' ],hosts)
        if next_neigh != None:
            storeData.store_connectivity (cred, host,neighbour[ 'ifname' ],next_neigh,next_neigh_if )
            vis_neighbour += 1

    for nextroute in nn_vis_router:
        next_neigh,next_neigh_if = next_interface_connect ( nextroute[ 'ipaddress' ],'0x000000000000',l2l3,nn_snmp )
        if next_neigh != None:
            storeData.store_connectivity ( cred,host,nextroute[ 'if_next' ],next_neigh,next_neigh_if )

    return 0


def hosts_to_switchsANDrouters_connectivity(cred,hosts,l2l3_dev,dev_nn_snmp):
    i = 0
    while i < len ( hosts):
        host = hosts.pop ( i )
        get_host_l2l3_connectivity ( cred,host,l2l3_dev,dev_nn_snmp,hosts )
        hosts.insert ( i,host )
        i+=1

    return 0


def connectivity_discovery(cred,dev_snmp,dev_non_snmp):

    devices= get_switchs_routers_hosts(dev_snmp)

    #connectivity between switchs and routers
    if len(devices[0])>1:
        l2_l3_connectivity (cred,devices[0],dev_non_snmp)

    #connectivity between end hosts and switchs/routers
    hosts_to_switchsANDrouters_connectivity(cred,devices[1],devices[0],dev_non_snmp)
    return 0


def hosts_address_mac(hosts):
    mac_ip = []
    for host in hosts:
        mac_ip.append((host['interface']['address'],host['interface']['mac']))
    return mac_ip


def get_devices_from_db(cred):
    query = '''MATCH (n:device)
               WHERE n.InterfacesSnmp IS NOT NULL
               RETURN n.SystemInfo,n.InterfacesSnmp,n.Neighbour,n.NextHops
            '''
    result = storeData.match_from_neo4j(cred,query)
    snmp_devices = []
    for record in result:
        snmp_dev = dict(system= ast.literal_eval ( record[ "n.SystemInfo" ][ 0 ] ),
                        interfaces = ast.literal_eval(record["n.InterfacesSnmp"][0]),
                        neighbours= ast.literal_eval ( record[ "n.Neighbour" ][ 0 ] ),
                        nextRoute = ast.literal_eval(record["n.NextHops"][0]))
        snmp_devices.append(snmp_dev)
    # print snmp_devices

    query2= '''MATCH (n:device)
               WHERE n.InterfacesSnmp IS NULL AND n.InterfacesScan IS NOT NULL
               RETURN n.InterfacesScan;
            '''
    result2 = storeData.match_from_neo4j ( cred,query2 )
    nn_snmp_dev = []
    for record in result2:
        v = ast.literal_eval ( record[ "n.InterfacesScan" ][ 0 ] )
        nn_snmp_dev.append((v['address'],v['mac']))

    # print nn_snmp_dev

    query3='''MATCH (n:device)
              WHERE n.mac IS NOT NULL AND n.address IS NOT NULL
              RETURN n.address,n.mac;
            '''
    result3 = storeData.match_from_neo4j ( cred,query3 )
    for record in result3:
        nn_snmp_dev.append((''.join(record["n.address"]),''.join(record["n.mac"])))

    # print nn_snmp_dev
    # for k in nn_snmp_dev:
    #     print k[0]
    #     print k[1]
    return [snmp_devices,nn_snmp_dev]


def match_from_neo4j(cred):
    query = '''MATCH (n:device)
                   WHERE n.mac IS NOT NULL AND n.address IS NOT NULL
                   RETURN ID(n);
                '''
    result = storeData.match_from_neo4j ( cred,query )
    return result


def main(args):

    couchdb = db_auth.CouchDB ( )
    couchdb.dbname = 'scan-test123'
    neo4jdb = db_auth.Neo4jDB ( )
    neo4jdb.password = 'azerty159'
    cred = neo4jdb.get_Neo4j_credentials ( )
    # cred1 = couchdb.get_couchdb_credentials()
    # hosts = RetrieveData.get_hosts_info ( cred1 )
    # hosts_mac_ip = hosts_address_mac ( hosts )
    # print hosts_mac_ip
    devices = get_devices_from_db(cred)
    connectivity_discovery ( cred,devices[0],devices[1] )
    # query = '''MATCH (n:device)
    #            where n.InterfacesSnmp IS NOT NULL
    #            return n
    #            '''
    # query = '''MATCH (n:device)
    #            WHERE n.mac IS NOT NULL AND n.address IS NOT NULL
    #            RETURN ID(n);
    #         '''
    # result = storeData.match_from_neo4j ( cred,query )
    # for record in result:
    #     print record ['ID(n)']
    # query = '''MATCH (n:device)
    #            WHERE n.InterfacesSnmp =~ %s
    #            RETURN ID(n),n.InterfacesSnmp
    #             '''% (devices[0][0][ 'interfaces' ])
    # query = '''MATCH (n:device)
    #            RETURN ID(n),n.InterfacesSnmp
    #         '''% (str ( devices[0][0][ 'interfaces' ] ) )
    # print devices[0][0][ 'interfaces' ]
    # k =([str ( devices[0][0][ 'interfaces' ] ) ])
    # print k
    # result = storeData.match_from_neo4j ( cred,query )
    # print result
    # for record in result :
    #     print record['n.InterfacesSnmp']
    # print str([ str ( devices[0][0][ 'interfaces' ] ) ])
    # query1 = '''MATCH (n:device)
    #            RETURN n.InterfacesScan ;
    #         '''
    # query = '''MATCH (n:device)
    #            WHERE (ID(n)=%s)
    #            RETURN ID(n);
    #         '''%('3526')

    # query0 = '''UNWIND {siks} AS siks
    #             MATCH (n:device)
    #             WHERE n.InterfacesSnmp = siks['interfaces']
    #             RETURN ID(n),n.InterfacesSnmp;
    #         '''
    # result = match_from_neo4j(cred,query0,devices[0][0])
    # print result
    # for record in result:
    #     print record['n.InterfacesSnmp']
    #     print record['ID(n)']
        # print ['n.InterfacesScan']
        # if record["n.InterfacesScan"] != None:
        #     v =ast.literal_eval(record["n.InterfacesScan"][0])
        #     print v['mac']

    # result2= storeData.match_from_neo4j(cred,query)
    # # print json.loads(result2)
    # for record in result2:
    #     print result2[0]['ID(n)']

    # hosts = RetrieveData.get_hosts_info(cred1)
    # print hosts
    # hosts_mac_ip = hosts_address_mac(hosts)
    # print hosts_mac_ip
    # print  "SNMP Discovery"
    # dev = device_discovery(hosts_mac_ip)
    # print dev
    # storeData.insert_to_db(cred,storeData.query_scan(hosts[0]))
    # print storeData.query_scan ( hosts[ 0 ] )
    # print storeData.query_snmp ( dev[1][0] )

    # print "Storage to neo4j DB"
    # snmp_dev = dev[1][0]
    # snmp_dev = json.dumps(snmp_dev)
    # print snmp_dev
    # storeData.insert_to_db ( cred,storeData.query_snmp ( dev[1][0] ) )
    # storeData.insert_dev_to_db (cred, dev[0],dev[1],hosts)

    # connectivity_discovery(snmp_dev,non_snmp_dev)
    # couchdb = db_auth.CouchDB()
    # couchdb.dbname = 'scan-test123'
    # neo4jdb = db_auth.Neo4jDB()
    # neo4jdb.password = 'azerty159'
    # hosts = RetrieveData.get_hosts_info (couchdb )
    # cred = neo4jdb.get_Neo4j_credentials()
    # print cred
    # print hosts
    #
    # for host in hosts:
    #     print storeData.query2_construct(host)
    #     storeData.insert_to_db(cred,storeData.query2_construct(host))

    return 0


if __name__ == '__main__':
    import sys

    sys.exit(main(sys.argv))
