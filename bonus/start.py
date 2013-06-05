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

def callback(ts, pkt, iface, queues):
   
    if DEBUG:
      print "" 
    pass

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
  f = open("%s" % FILE, "rb")
  reader = dpkt.pcap.Reader(f)
  generator = reader.__iter__()

  































