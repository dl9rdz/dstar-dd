from dstar_dd import *
from bitarray import bitarray
import getopt
import sys
import logging
import os
import struct
import socket
from fcntl import ioctl

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002

# (incomplete)
# This is a simple test program for D-Star DD packet encoder
# Reads ethernet frames from either a pcap file or from a tap device
# and encodes them into a bitstream (one byte per bit) ready to be
# fed into a GMSK modulator

# D-Star header dat
# Flag 1 (1st byte of head) should be 0xC0 and Flag2/3 0x00 for D-Star DD
head = "\xC0\x00\x00"
rptr1 = "XX0XXX G"
rptr2 = "XX0XXX A"
your  = "CQCQCQ  "
my1   = "XX0YYY  "
my2   = "IDID"


def usage():
    print "Usage: "+sys.argv[0]+" [-v] [-h] [-t] [-l] [-u <ip:port>] [-p <pcapfile>] [outputfile]"
    print "    -h: Prints help (this text)"
    print "    -t: Creates a new TAP device for receiving network frames"
    print "    -p <pcapfile>: Reads network frames from PCAP file"
    print "    -v: Enables verbose mode (to stderr)"
    print "    -l: loop forever on pcap file"
    print "    -u <ip:port> write output to UDP port instead of file"
    print "    -b <n>: symbols per byte (1 or 8, bigendian)"
    print "    outputfile, if ommitted writes to stdout"

def main():
    logging.basicConfig(format='%(message)s')
    logger = logging.getLogger('dstardd')
    loop = 0
    pcap = ""
    device = ""
    packing = "1"
    ip = ""
    port = 0
    opts,args = getopt.getopt(sys.argv[1:], 'u:b:lvtp:h', ["help","tap","pcap="])
    for o,a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-t", "--tap"):
            device = "tap"
        elif o in ("-p", "--pcap"):
            pcap = a
        elif o in ("-v"):
            logger.setLevel(logging.DEBUG)
        elif o in ("-l"):
            loop = 1
        elif o in ("-u"):
            ip,port = a.split(':')
            port = int(port)
            assert (port>0) and (port<65536), "Invalid UDP port %s" % a
        elif o in ("-b"):
            packing = a
        else:
            assert False, "Invalid option "+o
    encoder = dstardd()

    header = head+rptr1+rptr2+your+my1+my2
    logger.info("D-Star packet header: "+repr(header))

    if(len(args)>0):
        outfile = args[0]
    else:
        outfile = "/dev/stdout"
    

    if port>0:
        logger.info("Writing output to UDP socket %s:%d" % (ip,port))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    else:
        logger.info("Output written to"+outfile)
        file = open(outfile, "wb")

    verbose = 0
    prefix = 16        # Length of 1/0... sequence before sync pattern
    spacing = 16   # Spacing (0 symbols) between frames
    # Dummy packet in case no source is specified
    data = "\xAA"*6 + "\x55"*6 + "\x08\x00"  # eth header
    data += "\x45\x00"+"\x00\x26"+"\x00\x00\x40\x00\x3F\x01\x00\x00"
    data += "\x2C"*4 + "\x00"*4   # 44.44.44.44 to 0.0.0.0
    data += "\x08\x00\x00\x00\x55\x66\x00\x01123456\x00\x00\x00\x00"
    if device == "tap":
        tap = os.open("/dev/net/tun", os.O_RDWR)
        itap = ioctl(tap, TUNSETIFF, struct.pack("16sH", "dstar%d", IFF_TAP))
        ifname = itap[:16].strip("\x00")
        print ("Allocated interface %s" % ifname)
    while True:
        if pcap:
            logger.info("Reading packet from PCAP file (not yet impl)")
            # TODO: Read from pcap file
        elif device == "tap":
            logger.info("Reading packet from TAP device")
	    data = os.read(tap, 2048)
            data = data[4:]
        # Now we have packet data in data
        bits = encoder.dstardd_encode(header, data)
        logger.info("packing is"+packing+"!")
        if packing == "1":
            logger.info("Writing 1S/b for bits "+str(len(bits)))
            bits[0] += 2
            b = ''.join(map(chr,bits))
            #for i in xrange(len(bits)):
            #    b = chr(bits[i]);
            if port: sock.sendto(b, (ip,port))
            else: file.write(b)
        elif packing == "8":
            ethheader = [1, 0]*prefix + [1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0]
            bits = ethheader + bits
            space = [0]*spacing
            bibi = bits + space 
            packbits = bitarray(bibi, endian='big')
            packed = packbits.tobytes()
            if port: sock.sendto(packed, (ip,port))
            else: file.write(packed)
        if loop==0:
            sys.exit(0)

if __name__ == "__main__":
    main()

