from mininet.topo import Topo

from mininet.net import Mininet

from mininet.node import CPULimitedHost

from mininet.link import TCLink

from mininet.util import dumpNodeConnections

from mininet.log import setLogLevel

from mininet.node import RemoteController

from mininet.cli import CLI

from threading import Thread

import threading

import time

import os

import random

from subprocess import Popen

import socket

 

CoreSwitchList = []

AggSwitchList = []

EdgeSwitchList = []

HostList = []

 

def topology(k):

  net = Mininet(host=CPULimitedHost, link=TCLink, controller = RemoteController)

  c1 = net.addController('c1',controller=RemoteController,ip='127.0.0.1',port = 6633)  

  POD = k

  pod = POD

  end = pod//2

  iCoreLayerSwitch = (k//2)**2

  iAggLayerSwitch = k*(k//2)

  iEdgeLayerSwitch = k*(k//2)

  iHost = iEdgeLayerSwitch * (k//2)

  SCount = 0

  for x in range(1, pod*(pod//2)+1):

    PREFIX = "s"

    EdgeSwitchList.append(net.addSwitch(PREFIX + str(x)))

    SCount = SCount+1    

    print("ESwitch[",SCount,"]")

 

  for x in range(SCount+1,SCount+pod*(pod//2)+1):

    PREFIX = "s"

    AggSwitchList.append(net.addSwitch(PREFIX + str(x)))

    SCount = SCount+1 

    print("ASwitch[",SCount,"]")

 

  for x in range(SCount+1,SCount+((pod//2)**2)+1):

    PREFIX = "s"

    CoreSwitchList.append(net.addSwitch(PREFIX + str(x)))

    SCount = SCount+1 

    print("CSwitch[",SCount,"]")

 

  f1 = open('/home/mininet/fat_tree/f1.txt', 'w')

  count = 0

  digit2 = 0

  digit3 = 0

  for a in range(0,pod):

    for b in range(0,pod//2):

      for c in range(2,2+(pod//2)):

        count = count+1

        digit2 = count//100

        digit3 = count//10000

        PREFIX = "h"

        #print "digit2:",digit2

        #print "digit3:",digit3

        #print "count:",count

        print("host ip:","10."+str(a)+"."+str(b)+"."+str(c))

        print("host mac:","00:00:00:"+str(digit3%100).zfill(2)+":"+str(digit2%100).zfill(2)+":"+str(count%100).zfill(2))

        f1.write(PREFIX + str(count) + " " + "00:00:00:"+str(digit3%100).zfill(2)+":"+str(digit2%100).zfill(2)+":"+str(count%100).zfill(2)+"\n")

        HostList.append(net.addHost(PREFIX + str(count),ip="10."+str(a)+"."+str(b)+"."+str(c),mac="00:00:00:"+str(digit3%100).zfill(2)+":"+str(digit2%100).zfill(2)+":"+str(count%100).zfill(2)))

  f1.close() 

  f2=open('/home/mininet/fat_tree/f2.txt', 'w')

  for x in range(0, iEdgeLayerSwitch):

    for y in range(0,end):

      net.addLink(EdgeSwitchList[x], HostList[end*x+y],bw=10)

      f2.write(str(HostList[end*x+y]) + " " + str(EdgeSwitchList[x])[1] + " " + str(y+1) +"\n")

  f2.close()

 

  print("iAggLayerSwitch=",iAggLayerSwitch)

  for x in range(0, iAggLayerSwitch):

    for y in range(0,end):

      net.addLink(AggSwitchList[x], EdgeSwitchList[end*(x//end)+y], bw=10)

 

 

  for x in range(0, iAggLayerSwitch, end):

    for y in range(0,end):

      for z in range(0,end):

        net.addLink(CoreSwitchList[y*end+z], AggSwitchList[x+y], bw=10)

 

  print("*** Starting network")

  net.build()

  c1.start()

  for sw in EdgeSwitchList:

    sw.start([c1])

  for sw in AggSwitchList:

    sw.start([c1])

  for sw in CoreSwitchList:

    sw.start([c1])

 

  print("Dumpling host connections")

  dumpNodeConnections(net.hosts)

 

  #use arp -s to add static mapping of MAC to IP in each host

  print("len(HostList):",len(HostList))

  for x in HostList:

    for y in HostList:

      if x!=y:

        y.cmd('arp -s '+x.IP()+' '+x.MAC())

 

  net.hosts[0].cmd("join /home/mininet/pyretic/pyretic/tutorial/f1.txt /home/mininet/pyretic/pyretic/tutorial/f2.txt > /home/mininet/pyretic/pyretic/tutorial/f3.txt")

  CLI(net)

  net.stop()

 

if __name__ == '__main__':

  #setLogLevel( 'info' )

  topology(2)

 
"""


from pyretic.lib.corelib import*

from pyretic.lib.std import *

from multiprocessing import Lock

from pyretic.lib.query import *

from collections import defaultdict

import os

 

#switches

switches = []

 

#myhost[srcmac]->(switch, port)

myhost={}

 

#adjacency map [sw1][sw2]->port from sw1 to sw2

adjacency=defaultdict(lambda:defaultdict(lambda:None))

 

def minimum_distance(distance, Q):

  min = float('Inf')

  node = 0

  for v in Q:

    if distance[v] < min:

      min = distance[v]

      node = v

  return node

 

def get_path (src,dst,first_port,final_port):

  #Dijkstra's algorithm

  print("src=",src," dst=",dst, " first_port=", first_port, " final_port=", final_port)

  distance = {}

  previous = {}

  for dpid in switches:

    distance[dpid] = float('Inf')

    previous[dpid] = None

 

  distance[src]=0

  Q=set(switches)

 

  while len(Q)>0:

    u = minimum_distance(distance, Q)

    Q.remove(u)

 

    for p in switches:

      if adjacency[u][p]!=None:

        w = 1

        if distance[u] + w < distance[p]:

          distance[p] = distance[u] + w

          previous[p] = u

  r=[]

  p=dst

  r.append(p)

  q=previous[p]

  while q is not None:

    if q == src:

      r.append(q)

      break

    p=q

    r.append(p)

    q=previous[p]

  r.reverse()

  if src==dst:

    path=[src]

  else:

    path=r

 

  # Now add the ports

  r = []

  in_port = first_port

  for s1,s2 in zip(path[:-1],path[1:]):

    out_port = adjacency[s1][s2]

    r.append((s1,in_port,out_port))

    in_port = adjacency[s2][s1]

  r.append((dst,in_port,final_port))

  return r

 

class find_route(DynamicPolicy):

  def __init__(self):

    super(find_route,self).__init__()

    self.flood = flood()

    self.set_initial_state()

 

  def set_initial_state(self):

    self.query = packets(1,['srcmac','dstmac', 'srcip', 'dstip'])

    self.query.register_callback(self.myroute)

    self.forward = self.flood

    self.update_policy()

 

  def set_network(self,network):

    self.set_initial_state()

 

  def update_policy(self):

    self.policy = self.forward + self.query

 

  def myroute(self,pkt):

    print("In myroute()->",pkt['srcmac'], pkt['dstmac'], pkt['srcip'], pkt['dstip'])

    if ( str(pkt['srcmac']) not in myhost.keys() ) or (str(pkt['dstmac']) not in myhost.keys()):

      return

 

    #if match(ethtype=IP_TYPE):

    #  print "ipv4 packet"

 

    p1 = get_path(myhost[str(pkt['srcmac'])][0], myhost[str(pkt['dstmac'])][0],myhost[str(pkt['srcmac'])][1], myhost[str(pkt['dstmac'])][1])

    print(p1)

 

    r1 = parallel([(match(switch=a,srcip=pkt['srcip'],dstip=pkt['dstip']) >> fwd(c)) for a,b,c in p1])

    #print r1

 

    self.forward = if_(match(dstip=pkt['dstip'],srcip=pkt['srcip']),r1,self.forward)

    self.update_policy()

 

class find_switch(DynamicPolicy):

    def __init__(self):

        self.last_topology = None

        self.lock = Lock()

        super(find_switch,self).__init__()

 

    def set_network(self, network):

        with self.lock:

            for x in network.switch_list():

              switches.append(x)

 

            for (s1,s2,data) in network.topology.edges(data=True):

              adjacency[s1][s2]=data[s1]

              adjacency[s2][s1]=data[s2]

 

            self.last_topology = network.topology

 

def arp_and_ip():

  global myhost

  fin = open("/home/ubuntu/pyretic/pyretic/tutorial/f3.txt", "r")

  for line in fin:

    a=line.split()

    myhost[str(a[1])]=(int(a[2]), int(a[3]))

  fin.close()

  #print "myhost=", myhost

  #We don't need ARP packet, so we drop the ARP packets.

  return if_(match(ethtype=ARP_TYPE), drop, find_route())

   

def main():

  return ( find_switch() + arp_and_ip())
  
"""