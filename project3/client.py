#!/usr/bin/env python

# Milestone 1. HTTP Client  (20 points)
# You will begin by creating a simple client program. Start with the example program at:
# http://wiki.python.org/moin/TcpCommunication#Client

import sys
import socket
from optparse import OptionParser


def initialization(options, args):
  # numbers will be different, that's it.
  TCP_IP = '127.0.0.1'
  TCP_PORT = 5005
  BUFFER_SIZE = 1024
  MESSAGE = "Hello, World!"

  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((TCP_IP, TCP_PORT))
  s.send(MESSAGE)
  data = s.recv(BUFFER_SIZE)
  s.close()

  print "received data:", data



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


def dns_lookup(hostname):
  pass

if __name__ == "__main__":

  # Parse command-line arguments
  parser = OptionParser()
  parser.add_option("-d", "--debug", dest="debug", action="store_true", help="turn on debugging output", default=False)
  
  (options, args) = parser.parse_args()
  DEBUG = options.debug

  initialization(options, args)

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
  dns_lookup(url[0])

#   - Initiate a TCP connection to the server's IP address, port 80, using socket.socket

#   - Submit a valid HTTP 1.1 request for the desired URL 

#   - Parse the return code from the response

#   - If the request was successful ("200 OK"), read the entire data from the server and save the returned object to a file with the name given on the command line. Your client must support retrieving files of more than a few KB, which require multiple calls to your socket's recv() method.

#   - The command-line syntax for running your program will be: 
#     python client.py <URL> <filename> 
#     For example, to fetch http://www.cs.pdx.edu/index.html, 
#     python client.py http://www.cs.pdx.edu/index.html cs.html



