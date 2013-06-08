#!/usr/bin/env python

# Stacy Watts
# CS 594 - Internetworking Protocols
# Portland State University
# Spring 2013
# Program 3

# Milestone 2. HTTP Server  (20 points)
# Next, you will build a very simple web server. Start with the example 
# code at:  http://wiki.python.org/moin/TcpCommunication#Server
# The program will be run as
#       python server.py -p <port>

import sys
import socket
from optparse import OptionParser



# This began from the code at: http://wiki.python.org/moin/TcpCommunication#Server
def start_server(port):
  TCP_IP = '127.0.0.1'
  BUFFER_SIZE = 1024  

  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.bind((TCP_IP, port))

  # give it an argument: number queued up to send.  (check docs)  
  # even though single-threaded.
  s.listen(1)

  #this section in a loop so you don't close early.  
  conn, addr = s.accept()
  print 'Connection address:', addr
  while 1:
      data = conn.recv(BUFFER_SIZE)
      if not data: break
      print "received data:", data
      conn.send(data)  # echo
  return conn



# Main program
if __name__ == "__main__":

  # Parse command-line arguments
  parser = OptionParser()
  parser.add_option("-p", "--port", dest="p", help="port number", default="80")
  parser.add_option("-d", "--debug", dest="debug", action="store_true", help="turn on debugging output", default=False)
  
  (options, args) = parser.parse_args()
  DEBUG = options.debug
  # Extract the port from the command line
  port = int(options.p)

  # start server on specifed port
  s = start_server(port)

  # won't want to close til you're done.  
  s.close()

  # easier to program it like this, but multi-threading not so much.
  # multi-processing works better, but we don't have to.  
