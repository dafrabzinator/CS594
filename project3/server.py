#!/usr/bin/env python

import socket

#numbers will be different, that's it.  

TCP_IP = '127.0.0.1'
TCP_PORT = 5005
BUFFER_SIZE = 20  # Normally 1024, but we want fast response

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, TCP_PORT))

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

# won't want to close til you're done.  
conn.close()

# easier to program it like this, but multi-threading not so much.
# multi-processing works better, but we don't have to.  
