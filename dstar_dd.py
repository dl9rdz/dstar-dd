#                Simple D-STAR DD encoder/decoder stuff
#        (c) Copyright 2018 Hansi Reiser, dl9rdz@darc.de and others
#
#        SPDX-License-Identifier:	GPL-2.0+

# Note: just for testing purposes, not optimized for performance

import zlib
import numpy as np
from struct import *
from commpy.channelcoding.convcode import Trellis, conv_encode, viterbi_decode

class dstardd():
    sr = 0x7f;
    logger = None;

    # Scrambe / descrable data with pseudo random sequence
    # self.sr must be initialized before first call
    def scramble(self,s):
        ret = ['\x00'] * len(s)
        for i in xrange(len(s)): 
            if ( ((self.sr>>3) & 0x1) ^ (self.sr & 0x1) ) :
                self.sr >>= 1;
                self.sr  |= 64;
                ret[i] = (s[i] & 0x1 ) ^ 0x1;
            else:
                self.sr >>= 1;
                ret[i] = s[i] & 0x1
        return ret

    def deinterleave(self,s):
        ret = [0] * 660
        for i in xrange(12) :
            for j in xrange(28) :
                ret[i + j*24] = s[i*28 + j];
        for i in xrange(12,24) :
            for j in xrange(27) :
                ret[i + j*24] = s[i*27 + j + 12];
        return ret

    def convdecode(self, symbols):
	# better do only once:
        self.memory = np.array([2])
        self.g_matrix = np.array([[0o7, 0o5]])
        self.tr = Trellis(self.memory, self.g_matrix, 0, 'default')
	#
        x = list(chr(s+ord('0')) for s in symbols)
        bits = np.array(x)
        decoded = viterbi_decode(bits, self.tr, 15)
        return decoded

    #Decoder for DStar DD frames
    # header is an array of bits (0/1) (660 + 16 for len of data backet)
    # returns header as byte array, len as int
    def dstardd_decode_header(self, header):
        self.sr = 0x7f
        header = self.scramble(header)
        headerbits = self.deinterleave(header)
        headerbits = self.convdecode(headerbits)   
        data = ""
	for i in xrange(41):
            zeichen = 0
            for j in xrange(8): zeichen += headerbits[8*i+j] << j
            data += chr(zeichen)
        len = 0
        for i in xrange(2):
            for j in xrange(8): len += (header[660+i*8+j]&1)<<(i*8+j)
        if self.logger: self.logger.info("Decoded header data: "+repr(data))
        if self.logger: self.logger.info("Decoded len of payload: %d"%len)
        return data, len+4

    # Decoder for DStar DD frames -- payload
    # data is an array of bits (multiple of 8)
    def dstardd_decode_body(self, data):
        data = self.scramble(data)
        erg_pack = [0] * (len(data)/8)
        for i in xrange(len(data)/8):
            for j in xrange(8):
                erg_pack[i] |= (data[i*8+j] & 1) << j;
            erg_pack[i] = chr(erg_pack[i])
        if self.logger: self.logger.info("Decoded packet data: "+repr(erg_pack))
        return erg_pack

    # Encoder for DStar DD frames
    # header is a byte string with header data (3+8+8+8+8+4 bytes)
    # data is a byte string with ethernet frame (excluding CRC)
    # returns array of bits (0/1)
    def dstardd_encode(self, header, data):
        # Generate Header CRC
        genpoly = 0x8408;
        crc = 0xffff
        for i in xrange(39):
            crc ^= ord(header[i])
            for j in xrange(8):
                if(crc & 0x01):
	            crc >>= 1;
	            crc ^=    genpoly;
	        else:
	            crc >>=1 ;

        crc ^=    0xffff;
        print ("Header CRC: ",crc)
        header = header + chr(crc&0xff) + chr((crc>>8)&0xff)
        print ("Full header: ",repr(header));

        # Convolution of header block
        memory = np.array([2])
        g_matrix = np.array([[0o7, 0o5]])
        tr = Trellis(memory, g_matrix, 0, 'default')
        bits = np.array([0] * 660);
        for i in xrange(41):
            byte = ord(header[i])
            for j in xrange(8):
	        bits[i*8+j] = (byte>>j)&0x01;
        encoded = conv_encode(bits, tr)

        # Interleaving of header block
        interleaved = [0] * 660
        for i in xrange(12):
	    for j in xrange(28) :
	        interleaved[i*28 + j] = encoded[i + j*24];
	        
        for i in xrange(12,24) :
	    for j in xrange(27):
	        interleaved[i*27 + j + 12] = encoded[i + j*24];
        # Note: interleaved[i] enthaelt nun die 660header bits

        lenbits = [0]*16
        datalen = len(data)
        for i in xrange(16):
                lenbits[i] = (datalen>>i)&0x01

        databits = [0] * (datalen*8)
        for i in xrange(datalen):
                for j in xrange(8):
                        databits[i*8+j] = (ord(data[i])>>j) & 0x01

        content = chr(datalen&0xff) + chr((datalen>>8)&0xff) + data
        print("content for dstar crc: ", repr(content))
        dstarcrc = zlib.crc32(content) & 0xffffffff
        crcbits = [(dstarcrc>>i)&1 for i in range(0,32)]

        all = interleaved + lenbits + databits + crcbits

        # Scramble complete frame including header, data length and data
        self.sr = 0x7f
        all = self.scramble(all)
        return all
