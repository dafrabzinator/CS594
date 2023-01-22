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
import numpy as np
import matplotlib.pyplot as plt

from collections import defaultdict
from multiprocessing import Process, Queue
from queue import Full as QueueFullException

from optparse import OptionParser

import dpkt


DEBUG = False

SDEBUG = True

mac_tbl = {}
mac_tbl2 = {}
mac_tbl3 = {}
mac_tbl4 = {}

results1 = defaultdict(int)
list_of_results1 = []
results2 = defaultdict(int)
list_of_results2 = []
output_byts = [0] * 4

#variables used for Graphs command line
count2 = 0
output_cnt1 = [0] * 4

#variables used for Graphs 20
count3 = 0
output_cnt2 = [0] * 4

#variables used for Graphs 40
count4 = 0
output_cnt3 = [0] * 4

#variables used for Graphs 100
count5 = 0
output_cnt4 = [0] * 4

def get_packet(g):
    packet = None
    try:
        packet = g.next()
    except StopIteration:
        packet = None
    return packet


def run_output_interface(iface_num, q, trans_delay):
    filename = "./output-%d.pcap" % iface_num
    f = open(filename, "wb")
    writer = dpkt.pcap.Writer(f)
    while True:
        p = q.get()
        if p is None:
            writer.close()
            f.close()
            break
        ts, pkt = p
        if SDEBUG:
            time.sleep(trans_delay)
        writer.writepkt(pkt, ts+trans_delay)


def callback(ts, pkt, iface, queues):
##Show the 10 biggest senders (identified by MAC address), by number of frames
##Show the 10 biggest senders by number of total bytes
##Show the total number of frames and total bytes written to each output interface
##Show how changes to the size of the MAC address table impact the output trafic volume
    global count2
    global output_cnt1
    list_of_results2.append([])
    
    source = pkt[6:12]
    destination = pkt[0:6]
    
    check = mac_tbl.get(destination)
    in_table = mac_tbl.get(source)
    
    
    list_of_results1.append(source)

    list_of_results2[count2].append(source)
    list_of_results2[count2].append(len(pkt))
    
    count2 += 1

    
    if check == None:
        for i in range (1, num_interfaces+1):
        # set the que to the all of other interfaces then what it
        # received. If i equals iface simply pass
            if iface == i:
                pass
            else:
                if DEBUG:
                    print ("Packet is from interface %d" % iface)
                    print ("Writing packet to interface %d" % (i))
                q = queues[i]
                try:
                    output_byts[i-1] += len(pkt)
                    output_cnt1[i-1] +=1
                    q.put( (ts,pkt) )
                except QueueFullException:
                    drop_count += 1
    else:
        q = queues[check]
        output_byts[check-1] += len(pkt)
        output_cnt1[check-1] +=1
        try:
            q.put( (ts,pkt) )
        except QueueFullException:
            drop_count += 1
        
                    
    if in_table == None:
        if  (len(mac_tbl) >= MAC_tbl_size):
            mac_tbl.popitem()
        mac_tbl[source] = iface


# COPY OF CALL BACK TO CHANGE MAC TABLE SIZE MANUALLY #50
def callback2(ts, pkt, iface, queues):
##Show the 10 biggest senders (identified by MAC address), by number of frames
##Show the 10 biggest senders by number of total bytes
##Show the total number of frames and total bytes written to each output interface
##Show how changes to the size of the MAC address table impact the output trafic volume
    global count3
    global output_cnt2
    
    source = pkt[6:12]
    destination = pkt[0:6]
    
    check = mac_tbl2.get(destination)
    in_table = mac_tbl2.get(source)
    
    
    
    count3 += 1

    
    if check == None:
        for i in range (1, num_interfaces+1):
        # set the que to the all of other interfaces then what it
        # received. If i equals iface simply pass
            if iface == i:
                pass
            else:
                if DEBUG:
                    print ("Packet is from interface %d" % iface)
                    print ("Writing packet to interface %d" % (i))
                q = queues[i]
                try:
                    output_cnt2[i-1] +=1
                    q.put( (ts,pkt) )
                except QueueFullException:
                    drop_count += 1
    else:
        q = queues[check]
        output_cnt2[check-1] +=1
        try:
            q.put( (ts,pkt) )
        except QueueFullException:
            drop_count += 1
        
                    
    if in_table == None:
        if  (len(mac_tbl2) >= 20):
            mac_tbl2.popitem()
        mac_tbl2[source] = iface
        
# COPY OF CALL BACK TO CHANGE MAC TABLE SIZE MANUALLY #100
def callback3(ts, pkt, iface, queues):
##Show the 10 biggest senders (identified by MAC address), by number of frames
##Show the 10 biggest senders by number of total bytes
##Show the total number of frames and total bytes written to each output interface
##Show how changes to the size of the MAC address table impact the output trafic volume
    global count4
    global output_cnt3
    
    source = pkt[6:12]
    destination = pkt[0:6]
    
    check = mac_tbl3.get(destination)
    in_table = mac_tbl3.get(source)
    
    
    count4 += 1

    
    if check == None:
        for i in range (1, num_interfaces+1):
        # set the que to the all of other interfaces then what it
        # received. If i equals iface simply pass
            if iface == i:
                pass
            else:
                if DEBUG:
                    print ("Packet is from interface %d" % iface)
                    print ("Writing packet to interface %d" % (i))
                q = queues[i]
                try:
                    output_cnt3[i-1] +=1
                    q.put( (ts,pkt) )
                except QueueFullException:
                    drop_count += 1
    else:
        q = queues[check]
        output_cnt3[check-1] +=1
        try:
            q.put( (ts,pkt) )
        except QueueFullException:
            drop_count += 1
        
                    
    if in_table == None:
        if  (len(mac_tbl3) >= 40):
            mac_tbl3.popitem()
        mac_tbl3[source] = iface
        
# COPY OF CALL BACK TO CHANGE MAC TABLE SIZE MANUALLY #1000
def callback4(ts, pkt, iface, queues):
##Show the 10 biggest senders (identified by MAC address), by number of frames
##Show the 10 biggest senders by number of total bytes
##Show the total number of frames and total bytes written to each output interface
##Show how changes to the size of the MAC address table impact the output trafic volume
    global count5
    global output_cnt4
    
    source = pkt[6:12]
    destination = pkt[0:6]
    
    check = mac_tbl4.get(destination)
    in_table = mac_tbl4.get(source)
    
    count5 += 1

    
    if check == None:
        for i in range (1, num_interfaces+1):
        # set the que to the all of other interfaces then what it
        # received. If i equals iface simply pass
            if iface == i:
                pass
            else:
                if DEBUG:
                    print ("Packet is from interface %d" % iface)
                    print ("Writing packet to interface %d" % (i))
                q = queues[i]
                try:
                    output_cnt4[i-1] +=1
                    q.put( (ts,pkt) )
                except QueueFullException:
                    drop_count += 1
    else:
        q = queues[check]
        output_cnt4[check-1] +=1
        try:
            q.put( (ts,pkt) )
        except QueueFullException:
            drop_count += 1
        
                    
    if in_table == None:
        if  (len(mac_tbl4) >= 100):
            mac_tbl4.popitem()
        mac_tbl4[source] = iface
    


if __name__ == "__main__":
    
    # Seed the random number generator
    random.seed()
    
    # Parse command-line arguments
    parser = OptionParser()
    parser.add_option("-n", "--num-interfaces", dest="n", help="number of interfaces", default="4")
    parser.add_option("-t", "--table-size", dest="t", help="size of MAC address table", default="10")
    parser.add_option("-d", "--debug", dest="debug", action="store_true", help="turn on debugging output", default=False)
    
    (options, args) = parser.parse_args()
    
    num_interfaces = int(options.n)
    MAC_tbl_size = int(options.t)
    DEBUG = options.debug
    
    
    # First, initialize our inputs
    generators = {}
    input_files = {}
    for i in range(1,num_interfaces+1):
        f = open("./input-%d.pcap" % i, "r")
        input_files[i] = f
        reader = dpkt.pcap.Reader(f)
        generator = reader.__iter__()
        generators[i] = generator
    
    # Initialize our output interfaces
    output_queues = {}
    output_interfaces = {}
    transmission_delay = 0.10
    for i in range(1,num_interfaces+1):
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
            print ("Next packet is from interface %d" % iface)
        
        # Inject some additional delay here to simulate processing in real time
        interarrival_time = ts-prev_ts
        if DEBUG:
            print ("Main driver process sleeping for %1.3fs" % interarrival_time)
        if SDEBUG:
            time.sleep(interarrival_time)
        prev_ts = ts
        
        # Call our callback function to handle the input packet
        callback(ts, pkt, iface, output_queues)
        callback2(ts, pkt, iface, output_queues)
        callback3(ts, pkt, iface, output_queues)
        callback4(ts, pkt, iface, output_queues)
        
        p = get_packet(generators[iface])
        if p is not None:
            # The individual input generators provide us with timestamps and packet contents
            ts, pkt = p
            # We augment this data with the number of the input interface before putting it into the heap
            # The input iface number will be helpful in deciding where to send the packet in callback()
            heapq.heappush(h, (ts, pkt, iface))
        else:
            if DEBUG:
                print ("Interface %d has no more packets" % iface)
    
    # Now that we're done reading, we can close all of our input files.
    for i in input_files.keys():
        input_files[i].close()
    
    # We also let our output interfaces know that it's time to shut down
    for i in output_queues.keys():
        output_queues[i].put(None)
    # And we wait for the output interfaces to finish writing their packets to their pcap files
    for i in output_interfaces.keys():
        output_interfaces[i].join()


    #For each item in the list add it to the dictionary
    #and increment up for each time it is added
    for result in list_of_results1:
        results1[result] += 1
    print ("Results for command line option: ")

    #sort the dictionary by the value of times it appears
    rSorted = sorted(results1, key=results1.get, reverse=True)
    print ("\n\n10 biggest senders by frames:")
    for i in range (0, 10):
        print ("%d. %s - %d" % ((i+1), rSorted[i].encode("hex"), results1[rSorted[i]]))

    
    #For each item in the list add it to the dictionary
    #and increment up by the size of the packet
    for result in list_of_results2:
        results2[(result[0])] += result[1]

    #sort the dictionary by the value of greatest size
    r2Sorted = sorted(results2, key=results2.get, reverse=True)
    print ("\n\n10 biggest senders by size:")
    for i in range(0, 10):
        print ("%d. %s - %d" % ((i+1), r2Sorted[i].encode("hex"), results2[r2Sorted[i]]))

    #Print Total Count of Packets
    print ("\n\n%d number of packets & size" % count2)
    #Print activity based on each packet
    for i in range (0,4):
        print ("Output Interface %d - %d packets - %d bytes" % ((i+1), output_cnt1[i], output_byts[i]))
    print ("%d Total Packets Sent" % (output_cnt1[0]+output_cnt1[1]+output_cnt1[2]+output_cnt1[3]))

    N = 4
    #place data in each slot based on results from above
    #slot 1 = table size of user
    #slot 2 = table size 50
    #slot 3 = table size 100
    #slot 4 = table size 1000
    

    ind = np.arange(N)  # the x locations for the groups
    width = 0.20       # the width of the bars

    fig = plt.figure()
    ax = fig.add_subplot(111)
    rects1 = ax.bar(ind, output_cnt1, width, color='r')
    rects2 = ax.bar(ind+width*1, output_cnt2, width, color='g')
    rects3 = ax.bar(ind+width*2, output_cnt3, width, color='b')
    rects4 = ax.bar(ind+width*3, output_cnt4, width, color='c')

    # add some
    ax.set_ylabel('Packets')
    ax.set_xlabel('Output Interface')
    ax.set_title('Performance by Table Size')
    ax.set_xticks(ind+width)
    ax.set_xticklabels( ('1', '2', '3', '4') )

    ax.legend( (rects1[0], rects2[0], rects3[0], rects4[0]), ('User', '20', '40', '100') )

    def autolabel(rects):
        # attach some text labels
        for rect in rects:
            height = rect.get_height()
            ax.text(rect.get_x()+rect.get_width()/2., 1.05*height, '%d'%int(height),
                    ha='center', va='bottom')

    autolabel(rects1)
    autolabel(rects2)
    autolabel(rects3)
    autolabel(rects4)
   

    plt.show()
