#!/usr/bin/python

#  Copyright (c) 2013 Charles V Wright <cvwright@cs.pdx.edu>
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  3. The names of the authors and copyright holders may not be used to
#     endorse or promote products derived from this software without
#     specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
#  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
#  THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
#  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
#  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
#  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
#  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
#  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
#  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import os
import sys
import time
import heapq
import random
import difflib
import matplotlib
import ipaddr
import struct
import socket


from threading import Thread, Event, Timer
from multiprocessing import Process, Queue
from Queue import Full as QueueFullException

from optparse import OptionParser

# dpkt is still off-limits for the most part
# This is only here to allow reading and 
# writing of pcap files.
import dpkt

# But the Ethernet module is fair game!
# Feel free to use this one:
from dpkt.ethernet import Ethernet
from dpkt.udp import UDP
from dpkt.rip import RIP

DEBUG = False

num_interfaces = 0
# dictionary for mac address table
mac_tbl = {}
# list of list for interface table
interface_tbl = []
fwd_tbl = []
fwd_tbl_srt = []
RCF = False

##
##
## Sited Sources May be Needed

def check_fwd(ck_add):
    global fwd_tbl_srt
    #Iterate through list from top to bottom returning the Forward address
    netwk = ipaddr.IPv4Address(ck_add)
    
    for i in fwd_tbl_srt:
        if netwk in i[0]:
            #returns the address found in the fwd_tbl
            return i[1]

def check_iface(ck_add):
    global interface_tbl
    #Relocate this code to a function called locate add a counter
    #Iterate through list from top to bottom returning the Forward address
    netwk = ipaddr.IPv4Address(ck_add)
    
    for i in interface_tbl:
        if netwk in i[1]:
            #retuns the interface port for the matched address
            return i[2]

def send_arp_resp(ts, iface, pkt, queues):
    global interface_tbl
    
    if DEBUG:
        print pkt.encode("hex")
    destIP = pkt[28:32]#slice from pkt sender IP
    destMac =  pkt[6:12]#slice from pkt sender Mac
    srcIP = pkt[38:42]#slide from pkt dest IP
    #Second Variable for Manipulation
    srcIP2 = srcIP
    #Construct in Dot Notation for use in function check_iface
    srcConst = str(int((srcIP2[0:1].encode("hex")), 16)) + "." + str(int((srcIP2[1:2].encode("hex")), 16)) + "." + str(int((srcIP2[2:3].encode("hex")), 16)) + "." + str(int((srcIP2[3:4].encode("hex")), 16))
    catch = check_iface(srcConst)
    srcMac =  interface_tbl[int(catch)][0]
    #split mac address to remove :
    srcMac = srcMac.split(":")
    #Change to Int then Binary and Concatenate
    srcMacT = chr(int(srcMac[0], 16))
    srcMacT += chr(int(srcMac[1], 16))
    srcMacT += chr(int(srcMac[2], 16))
    srcMacT += chr(int(srcMac[3], 16))
    srcMacT += chr(int(srcMac[4], 16))
    srcMacT += chr(int(srcMac[5], 16))
    if DEBUG:
        print srcMacT.encode("hex")

    #rewrite items pkt
    pkt = destMac +  pkt[6:]
    pkt = pkt[:6] + srcMacT + pkt[12:]
    pkt = pkt[:21] + chr(2) + pkt[22:]
    pkt = pkt[:22] + srcMacT + pkt[28:]
    pkt = pkt[:28] + srcIP + pkt[32:]
    pkt = pkt[:32] + destMac + pkt[38:]
    pkt = pkt[:38] + destIP
    if DEBUG:
        print pkt.encode("hex")

    #prep for sending
    q = queues[iface]
    try:
        q.put( (ts,pkt) )
    except QueueFullException:
        drop_count += 1

#send updates to all neighbors
#use dictionary to add neighbor IP addresses from forwarding table
def send_rte_update():
    pass

#function used to return true if route exists and is already
def checkRoute(netwk, ipAd, metr):
    for i in fwd_tbl_srt:
        if netwk in i[0]:
            if ipAd in i[1]:
                if metr == i[3]:
                    i[4].cancel()
                    i[4].start()
                    return True
                elif metr == 16:
                    i[4].cancel()
                    removeEntry(netwk, ipAd)
                    RCF = True
                    return True
                else:
                    i[3] = metr
                    i[4].cancel()
                    i[4].start()
                    RCF = True
                    return True
            #returns the address found in the fwd_tbl
        else:
            return False

def removeEntry(netwk, ipAd):
    for i in fwd_tbl_srt:
        if netwk in i[0]:
            if ipAd in i[1]:
                i[4].close()
                del fwd_tbl_srt[i]

def processRip(pkt, iface, queues):
    global RCF
    global fwd_tbl
    global fwd_tbl_srt
    
    RCF = False
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data
    udp = ip.data
    rip = dpkt.rip.RIP(udp.data)
    for rte in rip.rtes:
        #Process algorithm
        
        #Calculate net mask
        nMask = '{0:32b}'.format(rte.subnet)
        count = 0
        for i in range(0,31):
            if nMask[i] == "1":
                count = 0
            else:
                count +=1
        nMask = 32 - count
        
        if DEBUG:
            print "Net Mask is %d" % nMask
        
        #Convert int to IP for address from http://snipplr.com/view/14807/
        octet = ''
        for exp in [3,2,1,0]:
            octet = octet + str(rte.addr / ( 256 ** exp )) + "."
            rte.addr = rte.addr % ( 256 ** exp )
        dotAddr = (octet.rstrip('.'))
        if DEBUG:
            print dotAddr
        dotAddr = dotAddr + "/" +   str(nMask)
        if DEBUG:
            print dotAddr
        dotAddr = ipaddr.IPv4Network(dotAddr)

        #Convert int to IP for hop address from http://snipplr.com/view/14807/
        octet = ''
        for exp in [3,2,1,0]:
            octet = octet + str(rte.next_hop / ( 256 ** exp )) + "."
            rte.next_hop = rte.next_hop % ( 256 ** exp )
        dotHop = (octet.rstrip('.'))
        if DEBUG:
            print dotHop
        dotHop = ipaddr.IPv4Address(dotHop)

        #calculate the metric
        met = min(rte.metric+1, 16)
    
    
        #check for the route first
        if checkRoute(dotAddr, dotHop, met) is False:
            if rte.metric > 0 and rte.metric < 16:
                if DEBUG:
                    print "valid metric %d" % rte.metric
                #adding route to the table
                index = len(fwd_tbl)
                fwd_tbl.append([])
                fwd_tbl[index].append(dotAddr)
                fwd_tbl[index].append(dotHop)
                fwd_tbl[index].append(nMask)
                fwd_tbl[index].append(met)
                fwd_tbl[index].append(Timer(180, removeEntry, args=[fwd_tbl[index][0],fwd_tbl[index][1]]))
                RCF = True

    fwd_tbl_srt = sorted(fwd_tbl, key=lambda x: int(x[2]), reverse=True)
    if RCF:
        send_rte_update()
        
        

        
        
        if DEBUG:
            print "family %d" % rte.family
            print '{0:32b}'.format(rte.addr)
            print rte.addr
            print '{0:32b}'.format(rte.subnet)
            print rte.subnet
            print rte.next_hop


def router_init(options, args):
    global num_interfaces
    global interface_tbl
    global mac_tbl
    global fwd_tbl
    global fwd_tbl_srt
    
    # Open up interfaces config File
    f = open("/Users/tylerfetters/Desktop/CS594/test/Project2/Project2/Project2/interfaces.conf")
    line_cnt = 0
    for line in f:
        line = line.split()
        if line[0] == "#":
            pass
        else:
            interface_tbl.append([])
            interface_tbl[line_cnt].append(line[1])
            netwk = ipaddr.IPv4Network(line[2])
            interface_tbl[line_cnt].append(netwk)
            interface_tbl[line_cnt].append(line[0])
            line_cnt += 1
    # Set Number of interfaces found in file
    num_interfaces = line_cnt

    #Open up static mac table
    f = open("/Users/tylerfetters/Desktop/CS594/test/Project2/Project2/Project2/MAC-address-table.txt")
    for line in f:
        line = line.split()
        if line[0] == "#":
            pass
        else:
            mac_tbl[line[0]] = line[1]
            
    #Open up static forwarding table
    f= open("/Users/tylerfetters/Desktop/CS594/test/Project2/Project2/Project2/forwarding.conf")
    line_cnt = 0
    for line in f:
        line = line.split()
        if line[0] == "#":
            pass
        else:
            fwd_tbl.append([])
            sub_line = line[0].split("/")
            netwk = ipaddr.IPv4Network(line[0])
            ipAd = ipaddr.IPv4Address(line[1])
            fwd_tbl[line_cnt].append(netwk)
            fwd_tbl[line_cnt].append(ipAd)
            fwd_tbl[line_cnt].append(sub_line[1])
            fwd_tbl[line_cnt].append(1)
            fwd_tbl[line_cnt].append(Timer(180, removeEntry, args=[fwd_tbl[line_cnt][0],fwd_tbl[line_cnt][1]]))
            
            
            line_cnt += 1

    fwd_tbl_srt = sorted(fwd_tbl, key=lambda x: int(x[2]), reverse=True)
    if DEBUG:
        print fwd_tbl_srt


    if DEBUG:
        print "%d interfaces \n" %num_interfaces
        print "\n Interface Table"
        print interface_tbl
        print "\n Mac Address Table"
        print mac_tbl


def callback(ts, pkt, iface, queues):
    
    #The Response must be ignored if it is not from the RIP port. - Do Nothing

    #The datagram's IPv4 source address should be checked to see whether the
    #datagram is from a valid neighbor; the source of the datagram must be
    #on a directly-connected network.
    
    
    #catch IP then UDP
    if pkt[12:14].encode("hex") == "0800" and pkt[23:24].encode("hex") == "11" :
        #listen on port 502
        if pkt[36:38].encode("hex") == "0208":
            processRip(pkt, iface, queues)
                #The datagram's IPv4 source address should be checked to see whether the
                #datagram is from a valid neighbor; the source of the datagram must be
                #on a directly-connected network.
                #It is also worth checking to see whether the response is from one of the router's own addresses. - Do Nothing
        else:
            #verify no need to handle any other type of UDP packages
            return

    if pkt[12:14].encode("hex") == "0806":
        send_arp_resp(ts, iface, pkt, queues)
    
    #Test Look Up Return IPV4 address object based on longest prefix match
    catch = check_fwd('128.255.255.255')
    if DEBUG:
        print catch
    catch2 = check_iface('128.75.247.146')
    if DEBUG:
        print catch2


def get_packet(g):
  packet = None
  try:
    packet = g.next()
  except StopIteration:
    packet = None
  return packet


def run_output_interface(iface_num, q, trans_delay):
  filename = "/Users/tylerfetters/Desktop/CS594/test/Project2/Project2/Project2/output-%d.pcap" % iface_num
  f = open(filename, "wb")
  writer = dpkt.pcap.Writer(f)
  while True:
    p = q.get()
    if p is None: 
      writer.close()
      f.close()
      break
    ts, pkt = p
    time.sleep(trans_delay)
    writer.writepkt(pkt, ts+trans_delay)





if __name__ == "__main__":

  # Seed the random number generator
  random.seed()

  # Parse command-line arguments
  parser = OptionParser()
  parser.add_option("-i", "--interfaces", dest="i", help="interface configuration file", default="interfaces.conf")
  parser.add_option("-m", "--mac-addr-table", dest="m", help="MAC address table", default="MAC-address-table.txt")
  parser.add_option("-f", "--forwarding-table", dest="f", help="forwarding table", default="forwarding.conf")
  parser.add_option("-d", "--debug", dest="debug", action="store_true", help="turn on debugging output", default=False)
  
  (options, args) = parser.parse_args()
  DEBUG = options.debug

  router_init(options, args)
    

  # First, initialize our inputs
  generators = {}
  input_files = {}
  for i in range(num_interfaces):
    f = open("/Users/tylerfetters/Desktop/CS594/test/Project2/Project2/Project2/M2-test01/input-%d.pcap" % i, "rb")
    input_files[i] = f
    reader = dpkt.pcap.Reader(f)
    generator = reader.__iter__()
    generators[i] = generator

  # Initialize our output interfaces
  output_queues = {}
  output_interfaces = {}
  transmission_delay = 0.10
  for i in range(num_interfaces):
    output_queues[i] = Queue(10)
    output_interfaces[i] = Process(target=run_output_interface, args=(i, output_queues[i], transmission_delay))
    output_interfaces[i].start()

  # h is a heap-based priority queue containing the next available packet from each interface.
  h = []
  # We start out by loading the first packet from each interface into h.
  # We always use the heapq functions to access h; this way, we preserve the heap invariant.
  for iface in generators.keys():
    p = get_packet(generators[iface])
    if p is not None:
      ts, pkt = p
      heapq.heappush(h, (ts, pkt, iface))

  # Now we're ready to iterate over all the packets from all the input files.
  # By using the heapq functions, we guarantee that we process the packets in 
  # the order of their arrival, even though they come from different input files.

  ts = 0.0            # We keep track of the current packet's timestamp
  prev_ts = 0.0       # And the previous packet's timestamp

  # While there are packets left to process, process them!
  while len(h) > 0:
    # Pop the next packet off the heap
    p = heapq.heappop(h)
    # Unwrap the tuple.  The heap contains triples of (timestamp, packet contents, interface number)
    ts, pkt, iface = p
    if DEBUG:
      print "Next packet is from interface %d" % iface

    # Inject some additional delay here to simulate processing in real time
    interarrival_time = ts-prev_ts
    if DEBUG:
      print "Main driver process sleeping for %1.3fs" % interarrival_time
    time.sleep(interarrival_time)
    prev_ts = ts

    # Call our callback function to handle the input packet
    callback(ts, pkt, iface, output_queues)

    p = get_packet(generators[iface])
    if p is not None:
      # The individual input generators provide us with timestamps and packet contents
      ts, pkt = p
      # We augment this data with the number of the input interface before putting it into the heap
      # The input iface number will be helpful in deciding where to send the packet in callback()
      heapq.heappush(h, (ts, pkt, iface))
    else:
      if DEBUG:
        print "Interface %d has no more packets" % iface

  # Now that we're done reading, we can close all of our input files.
  for i in input_files.keys():
    input_files[i].close()

  # We also let our output interfaces know that it's time to shut down
  for i in output_queues.keys():
    output_queues[i].put(None)
  # And we wait for the output interfaces to finish writing their packets to their pcap files
  for i in output_interfaces.keys():
    output_interfaces[i].join()


