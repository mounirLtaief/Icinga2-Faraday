#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  test.py
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


def main(args):
	from neo4j.v1 import GraphDatabase, basic_auth

	driver = GraphDatabase.driver("bolt://localhost", auth=basic_auth("neo4j", "azerty159"))
	session = driver.session()

	# Insert data
	insert_query = '''
	UNWIND {pairs} AS pair
	MERGE (s1:Service {name: pair[0]})
	MERGE (s2:Service {name: pair[1]})
	MERGE (s1)-[:DEPENDS_ON]->(s2);
	'''

	data = [["CRM", "Database VM"], ["Database VM", "Server 2"],
			["Server 2", "SAN"], ["Server 1", "SAN"], ["Webserver VM", "Server 1"],
			["Public Website", "Webserver VM"], ["Public Website", "Webserver VM"]]


	session.run(insert_query, parameters={"pairs": data})

# Impact Analysis

	impact_query = '''
	MATCH (n:Service)<-[:DEPENDS_ON*]-(dependent:Service)
	WHERE n.name = {service_name}
	RETURN collect(dependent.name) AS dependent_services
	'''

	results = session.run(impact_query, parameters={"service_name": "Server 1"})
	for record in results:
		print(record)


# Dependency Analysis

	dependency_query = """
	MATCH (n:Service)-[:DEPENDS_ON*]->(downstream:Service)	
	WHERE n.name = {service_name}
	RETURN collect(downstream.name) AS downstream_services
	"""

	results = session.run(dependency_query, {"service_name": "Public Website"})
	for record in results:
		print(record)

# Statistics

	stats_query = """
	MATCH (n:Service)<-[:DEPENDS_ON*]-(dependent:Service)
	RETURN n.name AS service, count(DISTINCT dependent) AS dependents
	ORDER BY dependents DESC
	LIMIT 1
	"""

	results = session.run(stats_query)
	for record in results:
		print(record)


	session.close()
	return 0

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
