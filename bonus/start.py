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
import ipaddr
import struct
import socket

from multiprocessing import Process, Queue
from Queue import Full as QueueFullException

from optparse import OptionParser

import dpkt

DEBUG = False

# dictionary for streams table
stream_tbl = {}

def extract_flows(ts, pkt):
   
  if DEBUG:
    print "" 
  pass
  # strip off eth
  # dpkt.ip.src
  # dpkt.ip.dst
  # dpkt.tcp.sport
  # dpkt.tcp.dport
  # dpkt.tcp.data

  # information to tell us where this piece goes:
  # dpkt.tcp.seq give us the sequence number for reassembly.  

  # parse out the IPs and the ports

  # put all 6 pieces into the dict

  # return the modified dict


def get_packet(g):
  packet = None
  try:
    packet = g.next()
  except StopIteration:
    packet = None
  return packet

### might not actually need the writer, if we don't need to write out the streams to other files.
def run_output_interface(iface_num, q, trans_delay):
  filename = "output_file.pcap"
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

  # Parse command-line arguments
  parser = OptionParser()
  parser.add_option("-f", "--file", dest="file", help="input file containing streams", default="wikipedia_page.pcap")
  parser.add_option("-d", "--debug", dest="debug", action="store_true", help="turn on debugging output", default=False)

  (options, args) = parser.parse_args()
  DEBUG = options.debug
  FILE = options.file
  
  # First, initialize our inputs
  generator = {}

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
  extract_flows(ts, pkt)


