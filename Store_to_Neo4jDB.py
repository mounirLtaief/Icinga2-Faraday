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

from neo4j.v1 import GraphDatabase,basic_auth
import Topology_Discovery as tp
import json
import ast

# query0 = '''
#         UNWIND {host} AS host
#         MERGE (d:device { name: link[0]['hostname'],address: link[0]['address'],mac: link[0]['mac'] })
#         '''
#
# query1 = '''
#         UNWIND {host} AS host
#         MERGE (d:device { name: link[0]['hostname'],address: link[0]['address'],mac: link[0]['mac'] })
#         '''
#
# query3 = ('\n'
#           '        UNWIND {host} AS host\n'
#           '	    MERGE (d:device { hostname = "unknown",address: host[0],mac: host[1] })\n'
#           '        ')

# def identify_services(dev):
#     # serv[ 'name' ]
#     servnumber = 0
#     l = len ( dev[ 'services' ] )
#     query= ''',discoveredServices:%s''' %l
#     for serv in dev[ 'services' ]:
#         query += ''',services_%s:%s,service_%s_Desc:%s,service_%s_protocol:%s,service_%s_ports:%s,
#                     service_%s_status:%s'''%(servnumber,[str(serv[ 'name' ])],servnumber,[str(serv[ 'description' ])],
#                                              servnumber,[str(serv[ 'protocol' ])],servnumber,serv[ 'ports' ],
#                                              servnumber,[str(serv[ 'status' ])])
#         servnumber += 1
#
#     return query


# def identify_vuls(dev):
#     vulnumber = 0
#     l = len ( dev[ 'vuls' ] )
#     query = ''',discoveredVuls:%s''' %l
#
#     for vul in dev[ 'vuls' ]:
#         # description = (vul[ 'desc' ]).replace ( '\n','*' )
#         # description = description.replace(':','')
#         # description = description.replace ( '!','' )
#         # description = description.replace ( ' ','' )
#         # description = description.replace ( '/','g' )
#         # description = description.replace ( '','' )
#         # description = (vul[ 'desc' ]).split('\n')
#         # for desc in description:
#         #     d = desc.split(':')
#         #     if len(d) == 1:
#         #         query+=', vul_%s_desc: %s' %(vulnumber, d[0])
#         #     if len(d)>1:
#         #         query += ', vul_%s_desc_%s: %s' % (vulnumber,d[ 0 ],d[1])
#
#         type = vul[ 'type' ]
#         # ,vulnumber,description    ,vul_%s_desc:%s
#         query += ''',vul_%s:%s,vul_%s_desc:%s,vul_%s_resolution:%s,vul_%s_severity:%s,vul_%s_type:%s,
#                  vul_%s_impact_integrity:%s,vul_%s_impact_confidentiality:%s,vul_%s_impact_availability:%s,
#                  vul_%s_impact_accountability:%s''' % (vulnumber,[str(vul[ 'name' ])],vulnumber,[str(vul[ 'desc' ])],vulnumber,
#                                                        [str(vul[ 'resolution' ])],vulnumber,[str(vul[ 'severity' ])],vulnumber,
#                                                        [str(type)],vulnumber,[str(vul[ 'impact' ]['integrity'])],vulnumber,
#                                                        [str(vul[ 'impact' ]['confidentiality'])],vulnumber,
#                                                        [str(vul[ 'impact' ]['availability'])],vulnumber,[str(vul[ 'impact' ]['accountability'])])
#
#         if type == 'VulnerabilityWeb':
#             query += ''',vul_%s_website:%s''' % (vulnumber,[str(vul[ 'website' ])])
#         vulnumber += 1
#
#     return query

def query_scan(dev):

    # query2 = '''
    #             UNWIND {host} AS host
    #             MERGE (d:device { hostname: host['interface']['hostnames'],hostdescription : host['host']['description'],
    #             os : host['host']['os'],macInterface: host['interface']['mac'],addressInterface : host['interface']['address'],
    #             makInterface : host['interface']['mask'],gatewayInterface : host['interface']['gateway'],
    #             networkSegmentInterfaces : host['interface']['network_segment'],interfaceType : host['interface']['description']
    #          '''

    query = '''MERGE (d:device { Hostinfo: %s,InterfacesScan:%s,Services: %s,Vuls: %s})''' %([str(dev['host'])],
                                                                                           [str(dev['interface'])],
                                                                                           [ str ( dev[ 'services' ] ) ],
                                                                                           [ str ( dev[ 'vuls' ] ) ])
    # query = '''UNWIND {info} AS info
    #            MERGE (d:device { Hostinfo: info['host'],InterfacesScan: info['interface'],Services: info['service'],
    #            Vuls: info['vuls']});'''
    # query = '''MERGE (d:device { Hostinfo: %s,InterfacesScan:%s'''%([str(dev['host'])],[str(dev['interface'])])
    #
    # if dev[ 'services' ] == [] and dev[ 'vuls' ] == []:
    #     query += ''', running_services : "0", VulsNumber : "0"})'''
    #     return query
    #
    # if dev[ 'services' ]  != [] and dev[ 'vuls' ]  == []:
    #     # query2 += identify_services(dev)
    #     query += ''', running_services: %s,discoverredServices: %s,
    #      discoveredVuls : "0" })''' %(len(dev[ 'services' ]),[str(dev[ 'services' ])])
    #     return query
    #
    # if dev[ 'services' ] == [] and dev[ 'vuls' ]  != []:
    #     # query2 += identify_vuls(dev)
    #     query += ''',VulsNumber: %s, discoveredVuls: %s,
    #                 discoveredServices : "0" })''' % (len(dev['vuls']),[ str ( dev[ 'vuls' ] ) ])
    #     # query2 += ''', discoveredServices : "0" })'''
    #     return query
    #
    # if dev[ 'services' ] != [] and dev[ 'vuls' ] != 0:
    #     # query2 += identify_services ( dev )
    #     # query2 += identify_vuls ( dev )
    #     query += ''',running_services: %s,discoverredServices: %s,VulsNumber: %s,
    #                 discoveredVuls: %s })''' % (len(dev[ 'services' ]),[ str ( dev[ 'services' ] ) ],
    #                                             len(dev['vuls']),[ str ( dev[ 'vuls' ] ) ])
    #     # query2 += ''',VulsNumber: %s,discoveredVuls: %s''' % (len(dev['vuls']),[ str ( dev[ 'vuls' ] ) ])
    #     # query2 += '''})'''
    # return query

    return query


def insert_to_db(cred,insert_query):
    driver = GraphDatabase.driver ( cred[ 0 ],auth=basic_auth ( cred[ 2 ],cred[ 1 ] ) )
    session = driver.session ( )
    # session.run ( insert_query[ 0 ],parameters={"host": insert_query[ 1 ]} )
    session.run ( insert_query)
    session.close ( )
    return 0


def verify_snmp(device,snmp_info):
    for dev in snmp_info:
        for interface in dev[ 'interfaces' ]:
            if interface[ 'ipaddress' ] == device[ 0 ]:
                if interface[ 'mac' ] == device[ 1 ] or device[ 1 ] == '0x000000000000':
                    return [ True,dev ]

    return [ False,None ]


def verify_scan(device,scan_info):
    for dev in scan_info:
        if dev[ 'interface' ][ 'address' ] == device[ 0 ]:
            if dev[ 'interface' ][ 'mac' ] == device[ 1 ] or device[ 1 ] == '0x000000000000':
                return [ True,dev ]
            if dev[ 'interface' ][ 'mac' ] == '0x000000000000':
                dev[ 'interface' ][ 'mac' ] = device[ 1 ]
                return [ True,dev ]

    return [ False,None ]


def query_snmp ( dev):
    query = '''MERGE (d:device {SystemInfo: %s,InterfacesSnmp:%s, Neighbour:%s,NextHops:%s })''' % ([ str ( dev[ 'system' ] ) ],
                                                                                                  [ str ( dev[ 'interfaces' ] ) ],
                                                                                                  [ str ( dev['neighbours' ] ) ],
                                                                                                  [ str ( dev['nextRoute' ] ) ])
    # query = '''UNWIND {info} AS info
    #         MERGE (d:device {SystemInfo: info[''],InterfacesSnmp:info[''], Neighbour:info[''],NextHops:info[''] })
    #
    #         '''
    # dev = json.loads(dev)
    # nextroute = str ( dev[ 'nextRoute' ] ).replace(' ','')
    # neighbour = str ( dev[ 'neighbours' ] ).replace(' ','')
    # interfaces = str ( dev[ 'interfaces' ] ).replace(' ','')
    # system = str ( dev['system' ] ).replace(' ','')
    # query = '''MERGE (d:device {SystemInfo: %s,InterfacesSnmp:%s, Neighbour:%s,NextHops:%s})" ''' % ([str(dev['system' ])],
    #                                                                                              [str(dev[ 'interfaces' ])],
    #                                                                                              [str(dev[ 'neighbours' ])],
    #                                                                                              [str(dev[ 'nextRoute' ])])
    return query


def query_scan_snmp(dev1,dev2):
    query = '''MERGE (d:device { Hostinfo: %s, InterfacesScan:%s, Services: %s, Vuls: %s, SystemInfo: %s, InterfacesSnmp:%s,
               Neighbour:%s, NextHops:%s })''' % ([ str ( dev1[ 'host' ] ) ],[ str ( dev1[ 'interface' ] ) ],[ str ( dev1[ 'services' ] ) ],
                                 [ str ( dev1[ 'vuls' ] ) ],[ str ( dev2[ 'system' ] ) ],[ str ( dev2[ 'interfaces' ] ) ],
                                 [ str ( dev2[ 'neighbours' ] ) ],[ str ( dev2['nextRoute' ] ) ])
    return query


def insert_dev_to_db(cred,devices,snmp_info,scan_info):

    for dev in devices:
        snmp_dev = verify_snmp ( dev,snmp_info )
        scan_dev = verify_scan ( dev,scan_info )
        if snmp_dev[ 0 ] and scan_info[ 0 ]:
            insert_to_db ( cred,query_scan_snmp( scan_dev[ 1 ],snmp_dev[ 1 ] ) )
        if snmp_dev[ 0 ] and not scan_dev[ 0 ]:
            insert_to_db ( cred,query_snmp ( snmp_dev[ 1 ] ) )
        if not snmp_dev[ 0 ] and scan_dev[ 0 ]:
            insert_to_db ( cred,query_scan( scan_dev[ 1 ] ) )
        if not snmp_dev[ 0 ] and not scan_dev[ 0 ]:
            query = '''MERGE (d:device {address: %s,mac: %s})'''%([str(dev[0])],[str(dev[1])])
            insert_to_db ( cred,query )

    return 0


def match_from_neo4j(cred,query):
    driver = GraphDatabase.driver ( cred[ 0 ],auth=basic_auth ( cred[ 2 ],cred[ 1 ] ) )
    session = driver.session ( )
    # session.run ( insert_query[ 0 ],parameters={"host": insert_query[ 1 ]} )
    result = session.run ( query )
    session.close ( )

    return result


def get_source_node(cred,src):
    query = '''MATCH (n:device)
               WHERE n.InterfacesSnmp IS NOT NULL
               RETURN ID(n),n.InterfacesSnmp;
            '''
    result = match_from_neo4j(cred,query)
    return get_id(result,src)
    # print json.loads(result)
    # print src
    # for record in result:
    #     # print record
    #     if record['n.InterfacesSnmp'] ==
    #     sourceID = record['ID(n)']
    # # print sourceID
    # return sourceID


def get_id(result,node):
    for record in result:
        interfaces = ast.literal_eval(record["n.InterfacesSnmp"][0])
        if node['interfaces'] == interfaces:
            return record['ID(n)']
    return None


def get_node_id(cred,node):
    query = '''MATCH (n:device)
               WHERE n.mac IS NOT NULL AND n.address IS NOT NULL
               RETURN ID(n),n.mac,n.address;
            '''
    result = match_from_neo4j ( cred,query )
    for record in result :
        if record['n.address'] == node[0] and record['n.mac']== node[1]:
            return record['ID(n)']
    return 0


def get_target_node(cred,dest):
    target = verfiy_target(cred,dest)
    # print target1
    if target[0]:
        return target[1]
    else:
        return get_node_id(cred,dest)
        # for record in target2:
        #     targetID = record['ID(n)']
            # print targetID
    return None


def verfiy_target(cred,dest):
    query1 = '''MATCH (n:device)
                    RETURN ID(n),n.InterfacesScan ;
                '''
    result = match_from_neo4j ( cred,query1 )
    for record in result:
        if record[ "n.InterfacesScan" ] != None:
            v = ast.literal_eval ( record[ "n.InterfacesScan" ][ 0 ] )
            if v['mac'] ==dest[1] and v['address'] == dest[0]:
                return [True,record['ID(n)']]

    return [False,None]


def insert_rel_type_0(cred,src,if_src,dest):

    sourceNodeID = get_source_node(cred,src)
    targetNodeID = get_target_node(cred,dest)
    # print sourceNodeID
    # print targetNodeID
    query = '''MATCH (d1:device),(d2:device)
               WHERE ID(d1) = %s AND ID(d2)=%s
               MERGE (d1)<-[l:CONNECTED_TO {interface_0:%s}]->(d2);
            '''%(sourceNodeID,targetNodeID,[ str ( if_src ) ])
    insert_to_db(cred,query)
    return 0


def insert_rel_type_1(cred,src,if_src,dest,if_dest):
    query = ''' MATCH (d:device)
                WHERE d.InterfacesSnmp IS NOT NULL
                RETURN ID(d),d.InterfacesSnmp;
            '''
    src_id = get_id(match_from_neo4j(cred,query),src)
    dest_id = get_id(match_from_neo4j(cred,query),dest)

    query_insert = '''MATCH (d1:device),(d2:device)
                      WHERE ID(d1) = %s AND ID(d2)=%s
                      MERGE (d1)<-[l:CONNECTED_TO {interface_0:%s}]->(d2);
                   ''' % (src_id,dest_id,[ str ( if_src ) ],[ str ( if_dest ) ])
    insert_to_db ( cred,query )
    # query = ''' MATCH (d1:device),(d2:device)
    #             WHERE d1.InterfacesSnmp = %s AND d2.InterfacesSnmp = %s
    #             MERGE (d1)<-[l:CONNECTED_TO {interface_0:%s,interface_1:%s}]->(d2);
    #         ''' %([ str ( src[ 'interfaces' ] ) ],[ str ( dest[ 'interfaces' ] ) ],[ str ( if_src ) ],[ str ( if_dest ) ])
    # match_from_neo4j(cred,query)
    return 0


def store_connectivity(cred,src,if_src,dest,if_dest):

    if if_dest == None:
        insert_rel_type_0(cred,src,if_src,dest)
    else:
        insert_rel_type_1(cred,src,if_src,dest,if_dest)

    return 0
