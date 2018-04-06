from dstar_dd import *
from bitarray import bitarray
import getopt
import sys
import logging
import os
import struct
import time
import binascii
import socket
import select
from subprocess import call
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

# D-Star header dat
# Flag 1 (1st byte of head) should be 0xC0 and Flag2/3 0x00 for D-Star DD
head = "\xC0\x00\x00"
rptr1 = "XX0XXX G"
rptr2 = "XX0XXX A"
your  = "CQCQCQ  "
my1   = "XX0YYY  "
my2   = "IDID"
header = head+rptr1+rptr2+your+my1+my2

# (incomplete)
# This is a simple test program for D-Star DD packet decoder
# Receives a bitstream (one byte per bit, second bit set for frame start)
# and decodes frames into either pcap files or a tap device

port = 0
file = None
sock = None
udpdata = None
datapos = 0

def usage():
    print "Usage: "+sys.argv[0]+" [-v] [-h] [-t] [-i <script>] [-u <ip:port>] [-p <pcapfile>]"
    print "    -h: Prints help (this text)"
    print "    -t: Creates a new TAP device for sending network frames"
    print "    -i <script>: Initialization script for TAP device"
    print "    -p <pcapfile>: Writes network frames to PCAP file"
    print "    -v: Enables verbose mode (to stderr)"
    print "    -u <ip:port:port>: Read and write UDP port"
    print "    -b <n>: symbols per byte (1 or 8, bigendian) for output"
    print "            (1: what is used by receiver; 8: good for gnuradio GMSK modulator)"

def readnextpacket():
    global port, udpdate, datapos, file, sock, datalog
    assert port, "Must have port"
    assert not (udpdata and (datapos<len(udpdate))), "readnextpacket should be called now"
    udpdata = sock.recv(4096)
    datapos = 0

def havenextbyte():
    if udpdata and (datapos<len(upddata)): return True
    return False

def nextbyte():
    global port, udpdata, datapos, file, sock, datalog
    if port:
        if udpdata and (datapos<len(udpdata)):
            datapos=datapos+1
            if datalog: datalog.write(udpdata[datapos-1])
            return udpdata[datapos-1]
        else:
            udpdata = sock.recv(4096)
            if len(udpdata)==0: return ''
            datapos = 1
            if datalog: datalog.write(udpdata[datapos-1])
            return udpdata[datapos-1]
    else:
        return file.read(1);
   
def handletransmit(tap, osock, ip, oport):
    global logger, decoder, header
    data = os.read(tap, 2048)
    logger.info("Got a new packet on TAP interface")
    bits = decoder.dstardd_encode(header, data)
    prefix = 32
    spacing = 16
    ethheader = [1, 0]*prefix + [1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0]
    bits = ethheader + bits
    space = [0]*spacing
    bibi = bits + space 
    packbits = bitarray(bibi, endian='big')
    packed = packbits.tobytes()
    osock.sendto(packed, (ip,oport))

def main():
    global port, udpdata, datapos, file, sock, datalog
    global logger, decoder
    datalog=open("datalog.out","wb")
    logging.basicConfig(format='%(message)s')
    logger = logging.getLogger('dstardd')
    loop = 0
    pcap = ""
    device = ""
    packing = "1"
    tapscript = None
    opts,args = getopt.getopt(sys.argv[1:], 'u:vti:p:h', ["help","tap","pcap="])
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
        elif o in ("-i"):
            tapscript = a
        elif o in ("-l"):
            loop = 1
        elif o in ("-b"):
            packing = a
        elif o in ("-u"):
            ip,iport,oport = a.split(':')
            oport = int(oport)
            iport = int(iport)
            assert (iport>0) and (iport<65536), "Invalid input UDP port %s" % a
            assert (oport>0) and (oport<65536), "Invalid output UDP port %s" % a
        else:
            assert False, "Invalid option "+o

    decoder = dstardd()
    decoder.logger = logger

    assert len(args)==0, "Invalid argument"

    logger.info("Input read from UDP: %s:%d" % (ip,iport))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    osock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((ip, iport))
    except socket.error, err:
        print ("Couldn't be a UDP server on %s:%d: %s" % (ip,port,err))
        raise SystemExit
    logger.info("Output set to UDP: %s:%d" % (ip,oport))

    if device == "tap":
        tap = os.open("/dev/net/tun", os.O_RDWR)
        itap = ioctl(tap, TUNSETIFF, struct.pack("16sH", "dstar%d", IFF_TAP|IFF_NO_PI))
        ifname = itap[:16].strip("\x00")
        print "Allocated interface %s" % ifname
        if tapscript:
            logger.info("Running setup script %s" % tapscript)
            call([tapscript, ifname])
    if pcap:
        pcap = open(pcap, "wb")
        pcap.write(binascii.a2b_hex(pcap_global_header))

    inputs = [ tap, sock ]
    outputs = [ ]
    while True:
        while not havenextbyte():
            readable, writable, exceptional = select.select(inputs, outputs, inputs)
            for s in readable:
                if s is tap:
                    handletransmit(tap, osock, ip, oport)
                if s is sock:
                    readnextpacket()
            for s in exceptional:
                logger.warn("Exception on input "+repr(s))

        al = nextbyte()
        if al == '': logger.warn("End of file"); break
        if ord(al)>=2:
            # Found start of message
            headlen_bits = 660 + 16  # header + len data packet
            raw_header = [0] * headlen_bits
            for i in xrange(headlen_bits):
                if i > 0:
                    al = nextbyte()
                raw_header[i] = ord(al[0]) & 1
            (header,maxb,crcok) = decoder.dstardd_decode_header(raw_header)
            logger.info("DStar header crc ok is "+repr(crcok))
            if crcok==False:
                logger.info("Skipping invalid D-Star frame")
                continue;  # Ignore frames with invalid header crc
            if(maxb>2000): maxb=2000
            datapack = [0] * (maxb*8)
            for i in xrange(maxb*8):
                al = nextbyte()
                datapack[i] = ord(al[0]) & 1;
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
                logger.info("Writing packet to TAP device")
	        os.write(tap, ''.join(data))


if __name__ == "__main__":
    main()

