CFLAGS=-g

.c.o:

all:	testrx testtx

testrx: dstardd.o crc32.o viterbi.o tap.o testrx.o
	gcc dstardd.o crc32.o viterbi.o tap.o testrx.o -o testrx -lm -lpthread -g

testtx: dstardd.o crc32.o viterbi.o tap.o testtx.o
	gcc dstardd.o crc32.o viterbi.o tap.o testtx.o -o testtx -lm -lpthread -g
