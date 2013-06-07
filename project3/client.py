#!/usr/bin/env python

# Stacy Watts
# CS 594 - Internetworking Protocols
# Portland State University
# Spring 2013
# Program 3

# Milestone 1. HTTP Client  (20 points)
# You will begin by creating a simple client program. Start with the example 
# program at: http://wiki.python.org/moin/TcpCommunication#Client

# The command-line syntax for running your program will be: 
#   python client.py <URL> <filename> 
#   For example, to fetch http://www.cs.pdx.edu/index.html, 
#   python client.py http://www.cs.pdx.edu/index.html cs.html
# To set debug, use python client.py <URL> <filename> --debug

import sys
import socket
from optparse import OptionParser

# global constants
PORT = 80  # default port.  port 80 is HTTP.  to change connection port, change this


# extracts the url by parsing out the slashes, checks for the leading http
# if found, removes it form the tokens and returns just the list of url components
# The first will always be the site, the last will be the page if specified.
## Future modification suggestion:  parse the last element.  if it doesn't contain 
## "." character, add on to the tokens "index.html" as the default.
def extract_url(url):
  url = url.replace('//','/')
  tokens = url.split('/')
  if tokens[0] == "http:":
    tokens = tokens[1:]
  if DEBUG:
    print "Tokenized url: %s" % tokens
  return tokens



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



# creates a valid HTTP request message format.
# does some small error checking for a valid request.  If no page is requested,
# requests index.html .
def create_message(tokens):
  message = "GET "
  if len(tokens) == 1:
    message = message + "/index.html"
  else:
    for i in range(1, len(tokens)):
      message = message + "/" + tokens[i]
    if "." not in tokens[len(tokens)-1]:
      message = message + "index.html"
  message = message + " HTTP/1.1\r\n"
  message = message + "Host: " + tokens[0] + "\r\n\r\n"
  if DEBUG:
    print "Request to send: %s" % message
  return message



# send the request
def TCP_request(s, message):
  s.send(message)



# Take in the TCP response
def TCP_recv(s, length):
  BUFFER_SIZE = 1024
  if length == -1:
    data = s.recv(BUFFER_SIZE)
  else:
    data = s.recv(length)
  if DEBUG:
    print "\nReceived data:\n", data
  return data



# Close the socket
def TCP_close(s):
  s.close()



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
    print "Length was: %s" % length
  return code, length



# Main program
if __name__ == "__main__":

  # Parse command-line arguments
  parser = OptionParser()
  parser.add_option("-d", "--debug", dest="debug", action="store_true", help="turn on debugging output", default=False)
  
  (options, args) = parser.parse_args()
  DEBUG = options.debug

# Extract the hostname and URL from the command line
  url = sys.argv[1]
  filename = sys.argv[2]
  if DEBUG:
    print "Original url: %s" % url
    print "Filename for output: %s" %filename

  # extract just the pertinent portion, returned as tokens.
  url = extract_url(url)

  # Perform a DNS lookup to retrieve the IP address for the server 
  # using socket.gethostbyname()
  hostIP = dns_lookup(url[0])

  # Initiate a TCP connection to the server's IP address, port 80, using socket.socket
  s = start_TCP(hostIP, PORT)

  # Submit a valid HTTP 1.1 request for the desired URL 
  message = create_message(url)
  TCP_request(s, message)
  response = TCP_recv(s, -1)

  # Parse the return code from the response
  code, length = parse_response(response)
  if code == "200":  
    response = TCP_recv(s, length)
    

  # If the request was successful ("200 OK"), read the entire data from the 
  # server and save the returned object to a file with the name given on the 
  # command line. Your client must support retrieving files of more than a 
  # few KB, which require multiple calls to your socket's recv() method.

  # close the connection when finished.
  TCP_close(s)


