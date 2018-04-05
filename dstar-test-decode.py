from dstar_dd import *
from bitarray import bitarray
import getopt
import sys
import logging
import os
import struct
import time
import binascii
from fcntl import ioctl

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000   #raw ethernet on tap, no additonal header/proto indicator

pcap_global_header =   ('D4C3B2A1'
                        '0200'         #File format major revision (i.e. pcap <2>.4)  
                        '0400'         #File format minor revision (i.e. pcap 2.<4>)   
                        '00000000'
                        '00000000'
                        'FFFF0000'
                        '01000000')
pcap_packet_header =   ('SSSSSSSS'   # Timestamp (seconds)
                        'UUUUUUUU'   # Timestamp (useconts)
                        'XXXXXXXX'   #Frame Size (little endian) 
                        'YYYYYYYY')  #Frame Size (little endian)

# (incomplete)
# This is a simple test program for D-Star DD packet decoder
# Receives a bitstream (one byte per bit, second bit set for frame start)
# and decodes frames into either pcap files or a tap device

def usage():
    print "Usage: "+sys.argv[0]+" [-v] [-h] [-t] [-l] [-p <pcapfile>] [inputfile]"
    print "    -h: Prints help (this text)"
    print "    -t: Creates a new TAP device for sending network frames"
    print "    -p <pcapfile>: Writes network frames to PCAP file"
    print "    -v: Enables verbose mode (to stderr)"
    # print "    -l: loop forever (implicitely set for -p)"
    # print "    -b <n>: symbols per byte (1 or 8, bigendian)"
    print "    inputfile, if ommitted reads from stdin"

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

    decoder = dstardd()
    decoder.logger = logger

    #header = head+rptr1+rptr2+your+my1+my2
    #logger.info("D-Star packet header: "+repr(header))

    if(len(args)>0):
        infile = args[0]
    else:
        infile = "/dev/stdin"
    logging.info("Input read from "+infile)
    
    file = open(infile, "rb")

    verbose = 0
    if device == "tap":
        tap = os.open("/dev/net/tun", os.O_RDWR)
        itap = ioctl(tap, TUNSETIFF, struct.pack("16sH", "dstar%d", IFF_TAP|IFF_NO_PI))
        ifname = itap[:16].strip("\x00")
        print "Allocated interface %s" % ifname
        time.sleep(20)
        # bring device up
        # TODO... ret = ioctl(tap, cmd, req)
        
    if pcap:
        pcap = open(pcap, "wb")
        pcap.write(binascii.a2b_hex(pcap_global_header))

    while True:
        al = file.read(1);
        if al == '': logger.warn("End of file"); break
        if ord(al)>=2:
            # Found start of message
            headlen_bits = 660 + 16  # header + len data packet
            raw_header = [0] * headlen_bits
            for i in xrange(headlen_bits):
                if i > 0: al = file.read(1)
                raw_header[i] = chr(ord(al[0]) & 1 )
            (header,maxb) = decoder.dstardd_decode_header(raw_header)
            datapack = [0] * (maxb*8)
            for i in xrange(maxb*8):
                al = bytes(file.read(1));
                datapack[i] = chr( ord(al[0])&1 );
            data = decoder.dstardd_decode_body(datapack)

            # Expected CRC for ethernet frame with correct field order
	    #### moved to dstardd_decode_body
            #dat2 = ''.join(format(d, '02X') for d in erg_pack)
            #bindata = binascii.a2b_hex(dat2)
            #bindata = bindata[6:12] + bindata[0:6] + bindata[12:len(bindata)-4]
            #crc = zlib.crc32(bindata) & 0xffffffff
            #print ("calculated ethernet crc is %X" % crc)
	
            if pcap:
                logger.info("Writing packet to PCAP file")
                hex_len = "%08x"%(maxb)
                reverse = hex_len[6:] + hex_len[4:6] + hex_len[2:4] + hex_len[:2]
                pcaph = pcap_packet_header.replace('XXXXXXXX',reverse)
                pcaph = pcaph.replace('YYYYYYYY',reverse)
                tstamp = time.time()
                tss = "%08x"%int(tstamp)
		tsu = "%08x"%int( (tstamp-int(tstamp))*1000000 )
                pcaph = pcaph.replace('SSSSSSSS',tss[6:8]+tss[4:6]+tss[2:4]+tss[0:2])
                pcaph = pcaph.replace('UUUUUUUU',tsu[6:8]+tsu[4:6]+tsu[2:4]+tsu[0:2])
                pcap.write(binascii.a2b_hex(pcaph)+''.join(data))
            if device == "tap":
                logger.info("Writign packet to TAP device")
	        os.write(tap, ''.join(data))


if __name__ == "__main__":
    main()

