#!/usr/bin/env python

# Milestone 1. HTTP Client  (20 points)
# You will begin by creating a simple client program. Start with the example program at:
# http://wiki.python.org/moin/TcpCommunication#Client
# Requirements  For Milestone 1, your client must: 
#   - Extract the hostname and URL from the command line
#   - PerformaDNSlookuptoretrievetheIPaddressfortheserverusingsocket.gethostbyname()

#   - Submit a valid HTTP 1.1 request for the desired URL 
#   - Parse the return code from the response

#   - The command-line syntax for running your program will be: 
#     python client.py <URL> <filename> 
#     For example, to fetch http://www.cs.pdx.edu/index.html, 
#     python client.py http://www.cs.pdx.edu/index.html cs.html


import socket

def initialization()
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

if __name__ == "__main__":

  # Parse command-line arguments
  parser = OptionParser()
  parser.add_option("-i", "--interfaces", dest="i", help="interface configuration file", default="interfaces.conf")
  parser.add_option("-m", "--mac-addr-table", dest="m", help="MAC address table", default="MAC-address-table.txt")
  parser.add_option("-f", "--forwarding-table", dest="f", help="forwarding table", default="forwarding.conf")
  parser.add_option("-d", "--debug", dest="debug", action="store_true", help="turn on debugging output", default=False)
  
  (options, args) = parser.parse_args()
  DEBUG = options.debug

  router_init(options, args)

