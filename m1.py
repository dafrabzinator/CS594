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

DEBUG = False

num_interfaces = 0

# our Global definitions

# dictionary for mac address table
mac_tbl = {}
# list of list for interface table
interface_tbl = []
fwd_tbl = []
fwd_tbl_srt = []

# Our new functions
##
##
## Cited Sources May be Needed

# credit: Tyler?
def check_fwd(ck_add):
    global fwd_tbl_srt
    #Relocate this code to a function called locate add a counter
    #Iterate through list from top to bottom returning the Forward address
    netwk = ipaddr.IPv4Address(ck_add)
    
    for i in fwd_tbl_srt:
        if netwk in i[0]:
            #returns the address found in the fwd_tbl
            return i[1]

# credit: Tyler?
def check_iface(ck_add):
    global interface_tbl
    #Relocate this code to a function called locate add a counter
    #Iterate through list from top to bottom returning the Forward address
    netwk = ipaddr.IPv4Address(ck_add)
    
    for i in interface_tbl:
        if netwk in i[1]:
            #retuns the interface port for the matched address
            return i[2]

# credit: Tyler?
def send_arp_resp(ts, iface, pkt, queues):
    global interface_tbl
    if DEBUG:
        print pkt.encode("hex")
    destIP = pkt[28:32]#slice from pkt sender IP
    destMac =  pkt[6:12]#slice from pkt sender Mac
    srcIP = pkt[38:42]#slide from pkt dest IP
    ###NEED TO CONVERT TO DOT NOTATION
    srcIP2 = srcIP
    srcConst = str(int((srcIP2[0:1].encode("hex")), 16)) + "." + str(int((srcIP2[1:2].encode("hex")), 16)) + "." + str(int((srcIP2[2:3].encode("hex")), 16)) + "." + str(int((srcIP2[3:4].encode("hex")), 16))
    catch = check_iface(srcConst)
    srcMac =  interface_tbl[int(catch)][0]
    srcMac = srcMac.split(":")
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
    print pkt.encode("hex")
    
    q = queues[iface]
    try:
        q.put( (ts,pkt) )
    except QueueFullException:
        drop_count += 1

# Written by Stacy
# Ignore Ethernet frames addressed to other devices on the LAN
# This function should take in an ethernet frame, check the MAC address to
# see if it is us on this interface.  If so, returns a 1.  If not, return "None".
def ethernet_for_us(packet, arrival_iface):
  global interface_tbl
  # first, turn the packet into readable ethernet:
  eth = dpkt.ethernet.Ethernet(packet)

  # now check our interface table to see if the interface it came in on matches
  # the MAC address being sent to.  If not, we ignore it. 
  strng = interface_tbl[arrival_iface][0]
  newstr = strng.replace(":", "")

  if (eth.dst.encode("hex") == newstr):
    if DEBUG:
      print "Arrival interface MAC %s" %interface_tbl[arrival_iface][0]
    return 1
  else:
    if DEBUG:
      print "Source and dest interfaces do not match"
    return 0

# Written by Stacy
# Function to forward IP packets to the proper outbound interface based on
# longest-prefix matching.  Takes in the ethernet packet, returns the interface
# to send out on.  
def forward_IP_packets_to_iface(packet):
  # get the destination IP out of the ethernet data payload (the IP packet)
  dest_ip = packet[30:34]
  dest_ip = dest_ip.encode("hex")

  # turn this into the quad address we stored the table as
  pretty_ip = str(int(dest_ip[0:2], 16)) + "." +  str(int(dest_ip[2:4], 16)) + "." + str(int(dest_ip[4:6], 16)) + "." + str(int(dest_ip[6:8], 16))

  if DEBUG:
    print "Destination IP: %s" %pretty_ip
  #Test Look Up Return IPV4 address object based on longest prefix match
  catch = check_fwd(pretty_ip)
  if DEBUG:
    print "IP of outgoing interface %s" %catch
  catch2 = check_iface(catch)
  if DEBUG:
    print "interface of the ip being sent to: %s \n" %catch2
  return catch2
  
# Written by Stacy
# verify checksum.  if invalid can drop the packet.
def valid_checksum(packet):
  # pull the expected checksum out of the header
  pkt_value = packet[24:26]
  packet_header = packet[14:34]
  
  sum = 0
  # compute the expected checksum
  ##### math: (14 +2i) to (14 +2i +2) add the numbers all together in hex
  for i in range(0, 10):
    if i != 5: 
      temp = packet_header[2*i:2*i+2].encode("hex")
      sum += int(temp, 16)
    else:
      pass
   
  ##### then do the 1's complement: div(result) + mod(result).  That's the expected.
  sum =   (sum % int('ffff', 16)) 
  calc_checksum = hex(sum ^ 0xFFFF)
  if DEBUG:
    print "Calculated xor checksum: %s" %calc_checksum
    print "Original checksum: %s" %pkt_value.encode("hex")

  if int(pkt_value.encode("hex"), 16) == int(calc_checksum, 16):
    if DEBUG:
      print "Checksums matched, value was: %s" %pkt_value.encode("hex")
    return 1
  else:
    if DEBUG:
      print "Checksums did not match, packet should drop."
    return 0  


def router_init(options, args):
    global num_interfaces
    global interface_tbl
    global mac_tbl
    global fwd_tbl
    global fwd_tbl_srt
    
    # Open up interfaces config File
#    f = open("/Users/tylerfetters/Desktop/CS594/test/Project2/Project2/Project2/interfaces.conf")
    f = open("M1-test04/interfaces.conf")
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
#    f = open("/Users/tylerfetters/Desktop/CS594/test/Project2/Project2/Project2/MAC-address-table.txt")
    f = open("M1-test04/MAC-address-table.txt")
    for line in f:
        line = line.split()
        if line[0] == "#":
            pass
        else:
            mac_tbl[line[0]] = line[1]
            
    #Open up static forwarding table
#    f= open("/Users/tylerfetters/Desktop/CS594/test/Project2/Project2/Project2/forwarding.conf")
    f= open("M1-test04/forwarding.conf")
    line_cnt = 0
    for line in f:
        line = line.split()
        if line[0] == "#":
            pass
        else:
            fwd_tbl.append([])
            sub_line = line[0].split("/")
            #Also superceed by ipaddr module
            #sub_add = sub_line[0].split(".")
            netwk = ipaddr.IPv4Network(line[0])
            ipAd = ipaddr.IPv4Address(line[1])
            fwd_tbl[line_cnt].append(netwk)
            fwd_tbl[line_cnt].append(ipAd)
            fwd_tbl[line_cnt].append(sub_line[1])
            
            # This code has been commented as the IPAddr module better manages this process
            #for s in sub_add:
                #s = int(s)
                #s = bin(s)
                #sub_n = s[2:10]
                #if sub_n.__len__() < 8:
                    #0's in front of base
                    #zeros = ""
                    #for i in range(sub_n.__len__(), 8):
                        #zeros += "0"
                    #sub_n = zeros + sub_n
                #sub_con += sub_n
            #entry = sub_con[0:int(sub_line[1])]
            #fwd_tbl[entry] = line[1]
            line_cnt += 1

    fwd_tbl_srt = sorted(fwd_tbl, key=lambda x: int(x[2]), reverse=True)
    if DEBUG:
        print "Forwarding Table:"
        print fwd_tbl_srt


    if DEBUG:
        print "%d interfaces \n" %num_interfaces
        print "\n Interface Table"
        print interface_tbl
        print "\n Mac Address Table"
        print mac_tbl


def callback(ts, pkt, iface, queues):
   
    if DEBUG:
      print "" 
    print ""
    #check if arp, if so send an arp response. 
    if pkt[12:14].encode("hex") == "0806":
        send_arp_resp(ts, iface, pkt, queues)
    
    # check if the packet is for us, otherwise ignore it.
    elif ethernet_for_us(pkt, iface) == 1:

      # verify checksum.  if invalid can drop the packet.
      if valid_checksum(pkt) == 1:
        outgoing_iface = forward_IP_packets_to_iface(pkt)
        print "Outgoing Interface: %s" %outgoing_iface
      
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
#  filename = "/Users/tylerfetters/Desktop/CS594/test/Project2/Project2/Project2/output-%d.pcap" % iface_num
  filename = "/Users/stacy/Desktop/CS 594/proj2/output_test/output-%d.pcap" % iface_num
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
#    f = open("/Users/tylerfetters/Desktop/CS594/test/Project2/Project2/Project2/input-%d.pcap" % i, "rb")
    f = open("M1-test04/input-%d.pcap" % i, "rb")
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


