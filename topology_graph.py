#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  topology_graph.py
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
import igraph as ig
import json
import urllib2
import plotly.plotly as py
import plotly
from plotly.graph_objs import *

def main(data,nodenb):
	data = json.loads(data)
	N=nodenb
	i=0
	edgenb =0
	L=len(data)
	#print len(data[i]['from'])
	while i< L:
		if len(data[i]['from'])> 1 :
			edgenb+=len(data[i]['from'])
		else:
			edgenb+=len(data[i]['to'])
		i+=1
	
	print edgenb
	#print data[0]['from'][0]
	Edges = []
	s=edgenb
	d=0
	for k in data:
		if len(k['from'])> 1 :
			for j in range(len(k['from'])) :
				#print "hhhhhh"
				#print str(k['from'][j])
				#Edges.append((str(k['from'][j]),str(k['to'])))
				Edges.append((s,d))
				s = s - 1
		else :
			for j in range(len(k['to'])) :
				if j==0 :
					d+=1
					#Edges.append((str(k['from']),str(k['to'][j])))
					Edges.append((s,d))
				if j < L :
					d+=1
					#Edges.append((str(k['to'][j]),str(k['to'][j+1])))
					Edges.append((d,d+1))
	print len(Edges)
	#Edges=[(data[k]['from'][k]['source'], data['links'][k]['target']) for k in range(edgenb)]
	G=ig.Graph(Edges, directed=False)
	labels=[]
	group=[]
	gr = 0
	for node in data:
		if len(node['from'])> 1 :
			for j in range(len(node['from'])) :
				labels.append(node['from'][j])
				labels.append(node['to'])
				group.append(gr)
				
		else :
			for j in range(len(node['to'])) :
				if j==0 :
					gr+=1
					labels.append(node['from'])
					labels.append(node['to'][j])
				if j < L :
					gr+=1
					labels.append(node['to'][j])
					labels.append(node['to'][j+1])
					group.append(gr)
		
		#if node['from'] > 1 :
			#labels.append(node['from'][nb])
		
	#group.append(node['group'])
	
	layt=G.layout('kk', dim=3)
	Xn=[layt[k][0] for k in range(N)]# x-coordinates of nodes
	Yn=[layt[k][1] for k in range(N)]# y-coordinates
	Zn=[layt[k][2] for k in range(N)]# z-coordinates
	Xe=[]
	Ye=[]	
	Ze=[]
	for e in Edges:
		Xe+=[layt[e[0]][0],layt[e[1]][0], None]# x-coordinates of edge ends
		Ye+=[layt[e[0]][1],layt[e[1]][1], None]
		Ze+=[layt[e[0]][2],layt[e[1]][2], None]
		plotly.tools.set_credentials_file(username='topvis', api_key='t9r5r5d8a9')

	trace1=Scatter3d(x=Xe,
               y=Ye,
               z=Ze,
               mode='lines',
               line=Line(color='rgb(125,125,125)', width=1),
               hoverinfo='none'
               )
	trace2=Scatter3d(x=Xn,
               y=Yn,
               z=Zn,
               mode='markers',
               name='actors',
               marker=Marker(symbol='dot',
                             size=6,
                             color=group,
                             colorscale='Viridis',
                             line=Line(color='rgb(50,50,50)', width=0.5)
                             ),
               text=labels,
               hoverinfo='text'
               )
	axis=dict(showbackground=False,
          showline=False,
          zeroline=False,
          showgrid=False,
          showticklabels=False,
          title=''
          )
	layout = Layout(
         title="Network topology (3D visualization)",
         width=1000,
         height=1000,
         showlegend=False,
         scene=Scene(
         xaxis=XAxis(axis),
         yaxis=YAxis(axis),
         zaxis=ZAxis(axis),
        ),
     margin=Margin(
        t=100
    ),
    hovermode='closest',
    annotations=Annotations([
           Annotation(
           showarrow=False,
           #text="Data source: <a href='http://bost.ocks.org/mike/miserables/miserables.json'>[1]</a>",
           xref='paper',
           yref='paper',
           x=0,
           y=0.1,
           xanchor='left',
           yanchor='bottom',
           font=Font(
           size=14
           )
           )
        ]),    )
	data=Data([trace1, trace2])
	fig=Figure(data=data, layout=layout)
	py.iplot(fig, filename='Topology1')
	return 0

#if __name__ == '__main__':
    #import sys
    #sys.exit(main(sys.argv))
