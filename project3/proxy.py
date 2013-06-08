#!/usr/bin/env python

# Stacy Watts
# CS 594 - Internetworking Protocols
# Portland State University
# Spring 2013
# Program 3

# Milestone 3. HTTP Proxy (20 points)
# You will then combine elements of your HTTP client and server to create 
# a simple HTTP proxy.
# Requirements  For Milestone 3, your proxy must: 
# +  Listen on the TCP port specified on the command line. 
# As above, the program will be run as       python proxy.py -p <port>


import sys
import socket
import os.path
from time import gmtime, strftime
from optparse import OptionParser


# global constants
PORT = 80  # default port.  port 80 is HTTP, to change connection port, change this
           # please note: this has only been tested with port 80.


# Take in the TCP response
def TCP_recv(s, length):
  response = ''
  BUFFER_SIZE = 1024
  if length == -1:
    response = s.recv(BUFFER_SIZE)
  else:
    while 1:
      data = s.recv(BUFFER_SIZE)
      response = response + data
      if not data: break
  return response



# takes in a request and returns a host.
def parse_request(response):
  host = ""
  path = ""
  for item in response.split("\n"):
    if "Host:" in item:
      host = item.split()
      host = host[1]
    if "GET" in item:
      path = item.split()
      path = path[1]
     
  if DEBUG:
    print "\nHost requested was: %s" % host
    print "\nPath requested was: %s" % path
  return host, path



# does a simple dns lookup based on the hostname provided.
# returns the first answer.  (note: returns the first if multiple answers)
def dns_lookup(hostname):
  hostIP = socket.gethostbyname(hostname)
  if DEBUG:
    print "URL IP address: %s " % hostIP
  return hostIP



# This began from the code at: http://wiki.python.org/moin/TcpCommunication#Client
# Takes in the host and port, starts the connection, returns the connection.
def start_TCP(hostIP, port):
  TCP_IP = hostIP
  TCP_PORT = port
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((TCP_IP, TCP_PORT))
  return s



# send the request
def TCP_request(s, message):
  s.send(message)



def parse_response(response):
  length = ""
  for item in response.split("\n"):
    if "HTTP/" in item:
      code = item.split()
    if "Length:" in item:
      length = item.split()
      length = int(length[1])
  # if we still don't have the length, try the other length location.
  if (length == ""):
    length = response.split("\r\n\r\n")
    length = length[1].split("\r", 2)
    length = int(length[0], 16)
     
  code = code[1]
  if DEBUG:
    print "\nResponse code was: %s" % code
    print "Length will be: %s bytes, getting the file." % length
  return code, length



# Close the socket
def TCP_close(s):
  s.close()



# This began from the code at: http://wiki.python.org/moin/TcpCommunication#Server
def start_server(port):
  TCP_IP = '127.0.0.1'
  BUFFER_SIZE = 1024  
  flag = True

  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.bind((TCP_IP, port))

  # give it an argument: number queued up to send.  (check docs)  
  # even though single-threaded.
  if DEBUG:
    print "Listening on port %s" % port
  s.listen(1)

  #this section in a loop so you don't close early.  
  while 1:
    conn, addr = s.accept()
    if DEBUG:
      print 'Connection address:', addr
    while 1:
        # get the request in
        request = TCP_recv(conn, -1)
        #data = conn.recv(BUFFER_SIZE)

        if not request: break
        if DEBUG:
          print "received data: %s" % request

        # Parse each request to extract the server name (from the Host: header) and the
        # requested URL path. You may assume that the Host header will always be present.
        # Parse the host from the response
        host, path = parse_request(request)
        # Look up the IP address for the given server 
        hostIP = dns_lookup(host)

        # Initiate a TCP connection to the server's IP address on port 80
        s = start_TCP(hostIP, PORT)

        # Copy the HTTP request to the server
        TCP_request(s, request)

        # Retrieve the HTTP response from the server, and forward it on to the client
        # Your proxy must support responses larger than a few KB, which require 
        # multiple calls to the sockets' recv() and send() methods.
        response = TCP_recv(s, -1)

        # Parse the return code from the response
        code, length = parse_response(response)

        # If the request was successful ("200 OK"), read the entire data from the 
        # server and save the returned object to a file with the name given on the 
        # command line. Your client must support retrieving files of more than a 
        # few KB, which require multiple calls to your socket's recv() method.
        data = ""
        if code == "200":  
          # put the first chunk into the file
        data = response.split("\r\n\r\n",2)
        data = data[1]
        # get and put the rest of it into the file
        data = data + TCP_recv(s, length)
        if DEBUG:
          print data
        
        # send the response
        conn.send(data)  # echo

        # Finally, your proxy must keep a log of each HTTP request that it serves. 
        # The log should be a text file, named log.txt, with each request 
        # represented by one line in the file. The format for the log is:
        #       server path IP 
        # So for example, if you retrieve http://www.example.com/index.html from IP 
        # address 1.2.3.4, the line in your log file would be:
        # www.example.com /index.html 1.2.3.4
        write_log_file(host, path, hostIP)

  # close the connection when finished.
  TCP_close(s)

  conn.close()
  #  flag = False


# writes out a log file to log.txt
# logs are of the format:   server path IP
def write_log_file(server, path, IP):
  f = open("log.txt", 'a+')
  log_message = server + " " + path + " " + IP + "\n"
  f.write(log_message)
  f.close()
  if DEBUG:
    print "%s saved to log.txt"% log_message



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
  # Listen on the TCP port specified on the command line. 
  s = start_server(port)


