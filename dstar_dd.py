#    Simple D-STAR DD encoder/decoder stuff
#    (c) Copyright 2018 Hansi Reiser, dl9rdz@darc.de and others
#
#    SPDX-License-Identifier:	GPL-2.0+

# Note: just for testing purposes, not optimized for performance

import zlib
import numpy as np
from commpy.channelcoding.convcode import Trellis, conv_encode, viterbi_decode

class dstardd_out():

  # Encoder for DStar DD frames
  # header is a byte string with header data (3+8+8+8+8+4 bytes)
  # data is a byte string with ethernet frame (excluding CRC)
  # returns array of bits (0/1)
  def dstardd_encode(this, header, data):
    # Generate Header CRC
    genpoly = 0x8408;
    crc = 0xffff
    for i in xrange(39):
      crc ^= ord(header[i])
      for j in xrange(8):
	if(crc & 0x01):
	  crc >>= 1;
	  crc ^=  genpoly;
	else:
	  crc >>=1 ;

    crc ^=  0xffff;
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
    # TODO: Check if bit order is right - should by LSB first
    #dstarcrc = ((d>>24)&0xff) | ((d>>16)&0xff)<<8 | ((d>>8)&0xff)<<16 | (d&0xff)<<24
    #crcbits = [(dstarcrc>>i)&1 for i in range(31,-1,-1)]
    crcbits = [(dstarcrc>>i)&1 for i in range(0,32)]

    all = interleaved + lenbits + databits + crcbits

    # Scramble complete header block including data length and data
    sr =0x7f
    for i in xrange(len(all)):
       if ( ((sr>>3)&0x1)^(sr&0x01) ):
	  sr >>=1
	  sr |= 64
	  all[i] = all[i] ^ 0x01;
       else:
	  sr >>= 1

    return all
