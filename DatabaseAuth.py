#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  DatabaseAuth.py
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


class Neo4jDB(object):

    def __init__(self):
        self.host = "bolt://localhost"
        self.password = ""
        self.dbname = "neo4j"

    def get_Neo4j_credentials(self):
        if self.password == "":
            return -1
        return [self.host,self.password,self.dbname]

    def set_neo4j_credentials(self,dbnames,hosts,passwords):
        self.host = hosts
        self.password = passwords
        self.dbname = dbnames
        return 0


class CouchDB(object):
    def __init__(self):
        self.host = "localhost"
        self.port = "5984"
        self.dbname = ""

    def get_couchdb_credentials(self):
        if self.dbname == "":
            return -1
        return [self.host,self.port,self.dbname]

    def set_couchdb_credentials(self,dbnames,hosts,ports):
        self.host = hosts
        self.port = port
        self.dbname = dbnames
        return 0


def get_couchdb_credentials():
    if couchdbname == None:
        return -1
    elif couchHost == None:
        return -1
    elif couchPort == None :
        return -1
    else:
        return [couchHost,couchPort,couchdbname]

    return -1


def set_couchdb_credentials(host,port,dbname):
    couchdbname = dbname
    couchHost = host
    couchPort=port

    return 0




