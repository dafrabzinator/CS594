#!/usr/bin/env python

# Milestone 1. HTTP Client  (20 points)
# You will begin by creating a simple client program. Start with the example program at:
# http://wiki.python.org/moin/TcpCommunication#Client
# Requirements  For Milestone 1, your client must: 
#   • Extract the hostname and URL from the command line
#   • PerformaDNSlookuptoretrievetheIPaddressfortheserverusingsocket.gethostbyname()
#   • Initiate a TCP connection to the server’s IP address, port 80, using socket.socket 
#   • Submit a valid HTTP 1.1 request for the desired URL 
#   • Parse the return code from the response
#   • If the request was successful (“200 OK”), read the entire data from the server and save the returned object to a file with the name given on the command line. Your client must support retrieving files of more than a few KB, which require multiple calls to your socket’s recv() method.
#   • The command-line syntax for running your program will be: 
#     python client.py <URL> <filename> 
#     For example, to fetch http://www.cs.pdx.edu/index.html, 
#     python client.py http://www.cs.pdx.edu/index.html cs.html


import socket

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
