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
import os.path
from time import gmtime, strftime
from optparse import OptionParser



# This began from the code at: http://wiki.python.org/moin/TcpCommunication#Server
def start_server(port):
  TCP_IP = '127.0.0.1'
  BUFFER_SIZE = 1024  
  flag = True

  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.bind((TCP_IP, port))

  # give it an argument: number queued up to send.  (check docs)  
  # even though single-threaded.
  s.listen(1)

  #this section in a loop so you don't close early.  
  conn, addr = s.accept()
  print 'Connection address:', addr
  while flag:
      # get the request in
      data = conn.recv(BUFFER_SIZE)
      if not data: break
      print "received data: %s" % data
      # parse the request
      file_requested = parse_request(data)
      # create the response to the request
      response = create_response(file_requested)
      print "Response sent: %s" % response
      # send the response
      conn.send(response)  # echo
      conn.close()
      flag = False
#  return conn



# takes in the request, spits out the requested file if a valid HTTP/1.1
# request was made.  If not, returns an empty string ""
def parse_request(request):
  request = request.split()
  if (request[0] == "GET") and (request[2] == "HTTP/1.1"):
    file_requested = request[1]
    if file_requested[0] == "/":
      file_requested = file_requested[1:]
  else:
    file_requested = ""
  return file_requested
  


def create_response(file_requested):

  response = "HTTP/1.1 "
  okflag = False

  # types of headers returned
  if file_requested == "":
    response += "400 Bad Request"
  elif (os.path.isfile(file_requested)):
    response += "200 OK"
    okflag = True
  else:
    print os.path.isfile(file_requested)
    response += "404 Not Found"
  
  # common headers to all responses
  response += "\r\n"
  response += "Date: %s\r\n" % strftime("%a, %d %b %Y %X GMT", gmtime())
  response += "Server: %s\r\n" % sys.platform
 
  # response addition if a valid request
  if okflag == True:
    response += "Content-Length: %s\r\n" % os.path.getsize(file_requested)
    response += "\r\n"
    # add the file to the response.
    f = open(file_requested, "rb")
    response += f.read()
    f.close()
  else:
    response += "Content-Length: 0\r\n"

  # closing line feed for either type
  response += "\r\n"
  return response
  


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
#  s.close()

  # easier to program it like this, but multi-threading not so much.
  # multi-processing works better, but we don't have to.  
