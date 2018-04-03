from dstar_dd import *
from bitarray import bitarray
import getopt
import sys
import logging

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
    print "Usage: "+sys.argv[0]+" [-v] [-h] [-t] [-l] [-p <pcapfile>] [outputfile]"
    print "    -h: Prints help (this text)"
    print "    -t: Creates a new TAP device for receiving network frames"
    print "    -p <pcapfile>: Reads network frames from PCAP file"
    print "    -v: Enables verbose mode (to stderr)"
    print "    -l: loop forever (implicitely set for -p)"
    print "    -b <n>: symbols per byte (1 or 8, bigendian)"
    print "    outputfile, if ommitted writes to stdout"

def main():
    logging.basicConfig(format='%(message)s')
    logger = logging.getLogger('dstardd')
    loop = 0
    pcap = ""
    device = ""
    packing = "1"
    opts,args = getopt.getopt(sys.argv[1:], 'b:lvtp:h', ["help","tap","pcap="])
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
        elif o in ("-b"):
            packing = a
        else:
            assert False, "Invalid option "+o
    encoder = dstardd_out()

    header = head+rptr1+rptr2+your+my1+my2
    logger.info("D-Star packet header: "+repr(header))

    if(len(args)>0):
        outfile = args[0]
    else:
        outfile = "/dev/stdout"
    logging.info("Output written to"+outfile)
    
    file = open(outfile, "wb")

    verbose = 0
    prefix = 16        # Length of 1/0... sequence before sync pattern
    spacing = 16   # Spacing (0 symbols) between frames
    # Dummy packet in case no source is specified
    data = "\xAA"*6 + "\x55"*6 + "\x08\x00"  # eth header
    data += "\x45\x00"+"\x00\x26"+"\x00\x00\x40\x00\x3F\x01\x00\x00"
    data += "\x2C"*4 + "\x00"*4   # 44.44.44.44 to 0.0.0.0
    data += "\x08\x00\x00\x00\x55\x66\x00\x01123456\x00\x00\x00\x00"
    while True:
        if pcap:
            logger.info("Reading packet from PCAP file (not yet impl)")
            # TODO: Read from pcap file
        elif device == "tap":
            logger.info("Reading packet from TAP device (not yet impl)")
        # Now we have packet data in data
        bits = encoder.dstardd_encode(header, data)
        logger.info("packing is"+packing+"!")
        if packing == "1":
            logger.info("Writing 1S/b for bits "+str(len(bits)))
            bits[0] += 2
            for i in xrange(len(bits)):
                b = chr(bits[i]);
                file.write(b)
        elif packing == "8":
            header = [1, 0]*prefix + [1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0]
            bits = header + bits
            space = [0]*spacing
            bibi = bits + space 
            packbits = bitarray(bibi, endian='big')
            packed = packbits.tobytes()
            file.write(packed)
        if loop==0:
            sys.exit(0)

if __name__ == "__main__":
    main()

