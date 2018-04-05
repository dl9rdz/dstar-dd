#! /usr/bin/env python
# -*- coding: utf-8 -*-
''' Korrektur der Routine dstarhd-4.py und funktionierendes System um eine Datei mit den Paketdaten einzulesen '''

from __future__ import print_function

import zlib
import socket
import os
import re, time, sys
import time
#import timeit
import array
from struct import *
# debian: python-bitarray
#from bitarray import bitarray # vereinfacht beim Debugging
# easy_install bitstring
from bitstring import BitArray, BitStream
import binascii

HOST, PORT = "localhost", 5577 # Lesen der binären Daten 
# PORT 5578 ist für das rückschreiben der Asciizeichen

headlen_bits=660+16; #(header + Len folgendes Datenpacket

pcap_global_header =   ('D4C3B2A1'
                        '0200'         #File format major revision (i.e. pcap <2>.4)  
                        '0400'         #File format minor revision (i.e. pcap 2.<4>)   
                        '00000000'
                        '00000000'
                        'FFFF0000'
                        '01000000')
pcap_packet_header =   ('AA779F47'  # real timestamp
                        '90A20400'
                        'XXXXXXXX'   #Frame Size (little endian) 
                        'YYYYYYYY')  #Frame Size (little endian)



class dstarhd_out():

  A=[]
  
  # SOCK_DGRAM is the socket type to use for UDP sockets
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  try:
    sock.bind(('', PORT))
  except socket.error, err:
    print ("Couldn't be a udp server on port %d : %s" % (PORT, err));
    raise SystemExit

  
  def __init__(self):
#    global raw_header, symbole2;
    self.raw_header= bytearray('B');
    self.symbole = bytearray('B'); 
    self.rett = bytearray('B');
#    raw_header= Byte * 661;
    self.raw_header=[0] * headlen_bits;
    self.symbole2 = [0] * headlen_bits;
    self.Data_pack = bytearray('B');
    self.Rest_pack = bytearray('B');
    self.Rest_pack=[0] * 2;
    self.Data_pack=[0] * 2600;
    self.all_data=bytearray('B');
#    self.all_data=[0] *3000;

    self.sr = 0x7f; # Shiftregister zum Descramble

  def addalldata (self,s,lang):
    for i in xrange(lang) :
      self.all_data=self.all_data + s[i];
      
      
  def descramble(self,s,lang):
#    global raw_header;
    #sr = 0x7f;
    for i in xrange(lang) : 
      if ( ((self.sr>>3) & 0x1) ^ (self.sr & 0x1) ) :
        self.sr >>= 1;
        self.sr  |= 64;
        s[i] = chr((ord(bytes(s[i])) & 0x1 ) ^ 0x1);
      else: 
        self.sr >>= 1;

  def deinterleave(self):
#    global raw_header, symbole2;
    for i in xrange(12) :
      for j in xrange(28) :
        self.symbole2[i + j*24] = chr(ord(self.raw_header[i*28 + j]) & 0xFF);
        
    for i in xrange(12,24) :
      for j in xrange(27) :
        self.symbole2[i + j*24] = chr(ord(self.raw_header[i*27 + j + 12]) & 0xFF);
	
    symbole_temp=bytearray(self.symbole2);
    self.symbole2=symbole_temp;


  def main(self):
#    global raw_header, symbole2;
    hdr=0
    lstr=''; al='';
    self.file = open("out.pktn")
    #self.file = open("./2018-complex-record-512k-decode-2.pktn");
    #self.file = open("testout.pktn")
    pcap = open("out.pcap","wb");
    pcap.write(binascii.a2b_hex(pcap_global_header));

#    self.file = open("/home/sdr/complex-record-512k-decode-1.pktn");
#    self.file = open("/home/sdr/complex-record-decoded-128k.bit");
    while True :
      #al = self.sock.recv(1);
      al = self.file.read(1);
      if al == '' : print ("Ende Datei"); break
      rxl=al;
#      al = chr(ord(al[0])+ord('0'));
      
      if ord(rxl) >= 2 :
	# Header gefunden
	T1=time.time();
	hdr+=1; 
	print ("\nHeader", hdr, " gefunden mit Wert:", ord(rxl), ", CHR:", ord(al),end=' ');
	print ("um Zeit:",time.strftime("%Y-%m-%d-%H:%M:%S"));
	start=time.time();
#	al = self.file.read(1);

	for i in xrange(headlen_bits) :
#	  al = self.sock.recv(1);
#	  al = self.file.read(1);
	  if i != 0 : al = self.file.read(1);
	  rxl=al; self.raw_header[i]=chr(ord(al[0]) & 1);
	  if i == 0 : print ("\nByte 0:",ord(self.raw_header[i]), " Ausgangswert:", ord(al));
#	  self.sock.sendto(rxl, (HOST, PORT+1))
	  momentan = time.time();
	  if (momentan-start)> 5 : break;
	self.rett = self.raw_header; # wird später gebraucht!!!
	# Descramble Header + Datenrecordlaenge (2 Bytes)
	self.sr = 0x7f;
	self.descramble(self.raw_header,headlen_bits);
	
	# verarbeite Header
	self.deinterleave();
	T2=time.time();
      
# Taeusche eine "Soft-Decision"-Dekodierung vor,
# indem "0" --> "0" bzw. "1" --> "31" ersetzt wird.
        for i in xrange(660) :
          self.symbole2[i] *= 31;
	symbole_temp=bytearray(self.symbole2);
	self.symbole2=symbole_temp;

# Analoge Werte fuer die Referenzsymbole
        High = 31;  # fuer die "5Bit-Quantisierung".
        Low  =  0;
        KillerMetrik = 400;

# Zustanduebergangsmatrix. Sie wird in der
# vorliegenden Implementierung nicht benoetigt!
#  char    T[4][2] = {{0, 1},
#                     {2, 3},
#                     {0, 1},
#                     {2, 3}};
        
# inverse Zustanduebergangsmatrix
        invT = [[0, 2, 0],[0, 2, 1],[1, 3, 0],[1, 3, 1]];
        
# Ausgabematrix fuer den ersten Bit als analoger Wert
        A1 = [[Low,  High],[High, Low],[High, Low],[Low,  High]];
        
# Ausgabematrix fuer den zweiten Bit als analoger Wert
        A2 = [[Low,  High],[Low,  High],[High, Low],[High, Low]];

# Metrik
        Metrik=[0] * 4;
        tempMetrik=[0]*4;
        
# Alternierende Speicherfelder fuer die dekodierten Daten
        Datenfolge_plus = [[0]*330 for x in xrange(4)];
        Datenfolge_minus = [[0]*330 for x in xrange(4)];
        
        datenbuffer = 1;
        Metrik_A = 0; Metrik_B = 0;
        j0 = 0;
        
# Initialisiere die Anfangsmetriken
        Metrik[0] = 0;
        Metrik[1] = KillerMetrik;
        Metrik[2] = KillerMetrik;
        Metrik[3] = KillerMetrik;
        
        for  k in xrange(330) :
          Symbol1 = (self.symbole2[2*k]);
          Symbol2 = (self.symbole2[2*k+1]);
#          temp1, temp2;
          
          for  S in xrange(4) :
            temp1 = Symbol1-A1[ invT[S][0] ][ invT[S][2] ];
            temp2 = Symbol2-A2[ invT[S][0] ][ invT[S][2] ];
            Metrik_A = Metrik[invT[S][0]] + temp1*temp1 + temp2*temp2;
            
            temp1 = Symbol1-A1[ invT[S][1] ][ invT[S][2] ];
            temp2 = Symbol2-A2[ invT[S][1] ][ invT[S][2] ];
            Metrik_B = Metrik[invT[S][1]] + temp1*temp1 + temp2*temp2;
            
            if Metrik_A < Metrik_B :
              tempMetrik[S] = Metrik_A;
              if (datenbuffer>0) :
                for j in xrange(j0,k) :
                  Datenfolge_plus[S][j] = Datenfolge_minus[invT[S][0]][j];

                Datenfolge_plus[S][k] = invT[S][2];
              else :
                for j in xrange(j0,k) :
                  Datenfolge_minus[S][j] = Datenfolge_plus[invT[S][0]][j];
                
                Datenfolge_minus[S][k] = invT[S][2];
              
            else :
              tempMetrik[S] = Metrik_B;
              if datenbuffer>0 :
                for j in xrange(j0,k) :
                  Datenfolge_plus[S][j] = Datenfolge_minus[invT[S][1]][j];
                
                Datenfolge_plus[S][k] = invT[S][2];
              else :
                for j in xrange(j0,k) :
                  Datenfolge_minus[S][j] = Datenfolge_plus[invT[S][1]][j];
                
                Datenfolge_minus[S][k] = invT[S][2];
              
            
# kopiere die temp-Metriken zurueck
          for  i in xrange(4) :
            Metrik[i] = tempMetrik[i];
          
          
# Erfahrungsgemaess stimmen alle Pfade bis auf den letzen relativ
# kurzen Stueck ueberein (s.g. Einschwingphaenomen). Deshalb reicht
# es auch aus, nur die aktuelsten (hier ca. 20) Elemente umzukopieren.
# Mit 30, basierend auf meinen Beobachtungen, ist man auf jeden Fall auf
# der sicheren Seite.
          if k>29 :
            j0 = k-30;
          
          datenbuffer *= -1;
        
        header="";
        for i in xrange(41) :
          zeichen = 0;
          
          if  Datenfolge_minus[0][i*8  ] : zeichen += (1<<0);
          if  Datenfolge_minus[0][i*8+1] : zeichen += (1<<1);
          if  Datenfolge_minus[0][i*8+2] : zeichen += (1<<2);
          if  Datenfolge_minus[0][i*8+3] : zeichen += (1<<3);
          if  Datenfolge_minus[0][i*8+4] : zeichen += (1<<4);
          if  Datenfolge_minus[0][i*8+5] : zeichen += (1<<5);
          if  Datenfolge_minus[0][i*8+6] : zeichen += (1<<6);
          if  Datenfolge_minus[0][i*8+7] : zeichen += (1<<7);
          
          header+=(chr(zeichen));
	T3=time.time();
#        print ;
 	print ("Header: ",repr(header));
	print ("RPTR 1:", header[3:11]);
	print ("RPTR 2:", header[11:19]); 
	print ("Your  :", header[19:27]); 
	print ("My 1  :", header[27:35]);  
	print ("My 2  :", header[35:39]);  

# Berechne CRC vom ganzen Header
#
# Generatorpolynom G(x) = x^16 + x^12 + x^5 + 1
# ohne die fuehrende 1 UND in umgekehrter Reihenfolge
        genpoly = 0x8408;
        
        crc = 0xffff;
        
        for i in xrange(39) :
          crc ^= ord(header[i]);
          for j in xrange(8) :
            if ( crc & 0x1 ) :
              crc >>= 1;
              crc ^= genpoly;
            else :
              crc >>= 1;
        crc ^= 0xffff;        # invertiere das Ergebnis
	crc_h= ((crc>>8)&0xFF) | ((crc << 8)&0xFF00)
	hex_crc= hex(crc_h);
	
	T4=time.time();
        
        print ("CRC   :", hex_crc);
	header_crc= (ord(header[39]) & 0xFF)<<8 | (ord(header[40])&0xFF);
	print ("CRC   :\t" ,end='');
	if crc_h==(header_crc) :
	  print ("OK"); crc_ok="OK"
	else : print ("ungleich"); crc_ok="nok"
#	print (crc_h,crc,header_crc, repr(zeichen));

	Zeile = time.strftime("%Y-%m-%d-%H:%M:%S:: ") + ">RPTR1:" \
		+ header[3:11]+ " >RPTR2:"+ header[11:19] \
		+ " >Your:" + header[19:27] + " >My1:" + header[27:35] \
		+ " >My2:" + header[35:39] + " >CRC: " + crc_ok + "\n";
#	print "Z:",Zeile;
#	Datei=open("header-dstar.log","a");
#	Datei.write(Zeile);
#	Datei.close();

	# header vollstaendig bearbeitet 
        
#	Data_pack=array.array('b'); Data_pack=[0]*(21*96)
#	for i in range(21*96) :
#	  al = self.sock.recv(1);
#	  rxl=al; Data_pack[i]=chr(ord(al[0]));
#	  al = chr(ord(al[0])+ord('0'));
	# lies die Datenpaket-Länge
	head_off = 660;
	self.Rest_pack = bytearray('\0\0');
	for i in xrange (2) :
	  for j in xrange(8) :
	    self.Rest_pack[i] = chr(ord(chr((ord(self.rett[head_off+i*8+j]) & 1) << (j))) | ord(chr(self.Rest_pack[i])));
#	print('Rest_pack =',str(self.Rest_pack)[:2]);
#	repr(self.Rest_pack[:2]);
	maxb=unpack('H',str(self.Rest_pack[:2]))[0];
	print('erkannte ENET-Packetlänge:',maxb);
	if(maxb*8>2600): maxb=0;
	maxb += 4; #DSTAR-Radio-packet-CRCbytes am Ende
        for i in xrange((maxb)*8) :
	  al = bytes(self.file.read(1)); rxl=al;
	  self.Data_pack[i] = chr(ord(al[0])&1);
        self.D_pack = array.array('B');
        self.D_pack = [0] * (maxb*8);
        j=0;
	for i in xrange(maxb*8):
          self.D_pack[j] = self.Data_pack[i];
          j+=1;

#	self.sr = 0x7f;
	self.descramble(self.D_pack,maxb*8);
	
	erg_pack = array.array('B'); erg_pack=[0]*(maxb);
	head_off=660;
	
	for i in xrange (maxb) :
	  for j in xrange(8) :
	    erg_pack[i] = ord(chr((ord(self.D_pack[i*8+j]) & 1) << (j))) | ord(chr(erg_pack[i]));
	
	# hier das ENET-Paket vollstädnig vorhanden
	
# zusätzliche Laengeninformation einfuegen;  ist jedoch nicht Bestandteil des ENet-Paketes, kann daher dafuer entfallen

	## das lassma mal wech:   erg_pack.insert(0,self.Rest_pack[1]); erg_pack.insert(0,self.Rest_pack[0]);
	
	for i in xrange(len(erg_pack)) :
          if i % 16 == 0 :
	    print ("\n%5d" % i,": ",end=''  );
	  if i % 8 == 0 : print (' ', end='');
          print ("{0:{width}X}".format(erg_pack[i],width=3),end='');
	for i in xrange(len(erg_pack)) :
          if i % 16 == 0 :
	    print ("\n%5d" % i,": ",end=''  );
	  if i % 8 == 0 : print (' ', end='');
          print ("{0:{width}d}".format(erg_pack[i],width=4),end='');
	b_a=BitArray(bytes=erg_pack);
	print("\nHex-Byte-String\n",b_a);
	T5=time.time();
	print("Zeiten:", T5-T1, T2-T1, T3-T2, T4-T3, T5-T4);
# write content in pcap format
 	hex_len = "%08x"%(maxb)
        reverse = hex_len[6:] + hex_len[4:6] + hex_len[2:4] + hex_len[:2]
	pcaph = pcap_packet_header.replace('XXXXXXXX',reverse)
	pcaph = pcaph.replace('YYYYYYYY',reverse)

	data = ''.join(format(d, '02X') for d in erg_pack)

	# Expected CRC for ethernet frame with correct field order
	dat2 = ''.join(format(d, '02X') for d in erg_pack)
	bindata = binascii.a2b_hex(dat2)
	bindata = bindata[6:12] + bindata[0:6] + bindata[12:len(bindata)-4]
	crc = zlib.crc32(bindata) & 0xffffffff
	print ("calculated ethernet crc is %X" % crc)

	erg_pack.insert(0,self.Rest_pack[1]); erg_pack.insert(0,self.Rest_pack[0]);
	dat2 = ''.join(format(d, '02X') for d in erg_pack)
	bindata = binascii.a2b_hex(dat2)
	#bindata = bindata[6:12] + bindata[0:6] + bindata[12:len(bindata)]
	bin4crc = bindata[0:6] + bindata[6:12] + bindata[12:len(bindata)-4]
	print ("bin4crc: ", repr(bin4crc))
	crc = zlib.crc32(bin4crc) & 0xffffffff
	print ("calculated dstar crc (with len field and swapped from/to) is %X" % crc)
	print ("crc in data stream is ", binascii.b2a_hex(bindata[len(bindata)-4:]))

# swap source and destination
	source = data[0:12]
	dest = data[12:24]
	data = pcaph + dest + source + data[24:]
	# data = pcaph + source + dest + data[12:]
	print ("data is ",data)
	data = binascii.a2b_hex(data)
	pcap.write(data) 

if __name__ == '__main__':
	tb = dstarhd_out()
	tb.main()
