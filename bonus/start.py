#!/usr/bin/python

# Stacy J Watts
# CS 594 - Internetworking Protocols at Portland State University
# Bonus Project
# TCP Stream reassembly
# Source is my modification of Professor Wright's original work.

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
import dpkt
import heapq
import ipaddr

from optparse import OptionParser

DEBUG = False



# Stacy's original work.
# utility to convert an ip input from binary to dotted-quad for human-readability.

def bin_to_IPv4(dest_ip):

  dest_ip = dest_ip.encode("hex")
  pretty_ip = str(int(dest_ip[0:2], 16)) + "." +  str(int(dest_ip[2:4], 16)) + "." + str(int(dest_ip[4:6], 16)) + "." + str(int(dest_ip[6:8], 16))

  return pretty_ip



# Stacy's original work.
# extracts the flow information from a packet
# places that flow information into the dictionary and returns it.  
# uses dpkt.tcp dpkt.ethernet dpkt.tcp 
# returns the modified dictionary of flows.

def extract_flows(ts, pkt, output_flows):

  if DEBUG:
    print "Packet at timestamp: %f" % ts

  # strip off eth
  # parse out the IPs and the ports
  eth = dpkt.ethernet.Ethernet(pkt)
  ip = eth.data
  tcp = ip.data

  # source and destination IPs human-readable:
  source_ip = bin_to_IPv4(ip.src)
  dest_ip = bin_to_IPv4(ip.dst)

  # create the 4-tuple key to the flows
  flow = (source_ip, dest_ip, tcp.sport, tcp.dport)

  # put all 6 pieces into the dict
  if flow in output_flows:
    output_flows[flow] += [(ts, tcp.data)]
  else:
    output_flows[flow] = [(ts, tcp.data)]
 
  # for the future of TCP reassembly, we will want: 
  # information to tell us where this piece goes, ie
  # dpkt.tcp.seq  
  # gives us the sequence number for reassembly.  
  # tcp.data length will give us the offset to work from.

  # return the modified dict
  return output_flows


def get_packet(g):
  packet = None
  try:
    packet = g.next()
  except StopIteration:
    packet = None
  return packet


if __name__ == "__main__":

  # Parse command-line arguments
  parser = OptionParser()
  parser.add_option("-f", "--file", dest="file", help="input file containing streams", default="wikipedia_page.pcap")
  parser.add_option("-d", "--debug", dest="debug", action="store_true", help="turn on debugging output", default=False)

  (options, args) = parser.parse_args()
  DEBUG = options.debug
  FILE = options.file
  
  # First, initialize our inputs
  generator = {}

  # dictionary for streams table
  output_flows = {}

  f = open("%s" % FILE, "rb")
  reader = dpkt.pcap.Reader(f)
  generator = reader.__iter__()

  # Initialize our output dictionary
  output_flows = {}

  # h is a heap-based priority queue containing the next available packet
  h = []
  # We start out by loading the first packet into h.
  # We always use the heapq functions to access h; this way, we preserve the heap invariant.
  p = get_packet(generator)
  if p is not None:
    ts, pkt = p
    heapq.heappush(h, (ts, pkt))

  # Now we're ready to iterate over all the packets from all the input files.
  # By using the heapq functions, we guarantee that we process the packets in 
  # the order of their arrival
  # This was kept so as to be able to handle multiple input files if needed in the future.
  
  ts = 0.0            # We keep track of the current packet's timestamp
  prev_ts = 0.0       # And the previous packet's timestamp

  # While there are packets left to process, process them!
  while len(h) > 0:
    # Pop the next packet off the heap
    p = heapq.heappop(h)
    # Unwrap the tuple.  The heap contains duples of (timestamp, packet contents)
    ts, pkt = p

    # Call extract-flows to add it to the dictionary of flows. 
    output_flows = extract_flows(ts, pkt, output_flows)

    p = get_packet(generator)
    if p is not None:
      # The individual input generator provides us with timestamps and packet contents
      ts, pkt = p
      heapq.heappush(h, (ts, pkt))
    else:
      if DEBUG:
        print "The input file has no more packets"

  # Now that we're done reading, we can close our input file.
  f.close()

  # for fun, it will display the streams to screen:
  for key in output_flows:
    print key
    print output_flows[key]
    print ""
  print "There were %s tcp streams counted.\n" % len(output_flows)
