#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # disable scapy warnings

from scapy.all import *
import sys
import os.path
import argparse

def expand(x):
    yield x.name
    while x.payload:
        x = x.payload
        yield x.name

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('filename')
    
    args = parser.parse_args()
    
    filename = args.filename;

    # make sure the file exists
    if not os.path.isfile(filename):
        print("Error: {0} is not a file".format(filename))
        sys.exit(0)

    pkts = rdpcap(filename)

    protos = {}
    for pkt in pkts:
        for t in expand(pkt):
            if not t in protos:
                protos[t] = 0
            protos[t] += 1

    print "Frequency\tProtocol"
    for p,n in protos.iteritems():
        print "{freq}\t{proto} ".format(proto=p, freq=n)

if __name__ == "__main__":
    main()
