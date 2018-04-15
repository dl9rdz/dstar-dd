#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <math.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#include "dstardd.h"
#include "tap.h"

typedef struct t_complexf {
	float I;
	float Q;
} complexf;

#define BLOCKSIZE 10240

#define SAMPLE_PER_BIT 4
#define FILTERLEN 0
int procbit(int bit);

// output file number
int output;
// TAP device
int tapfd;

int procsamples(complexf *samples, int n) {
	int max = n - FILTERLEN - 4;
		
	// decimation filter... none for now
	int i;
	complexf tmp[max];
	// can probably be optimized with
	// volk_32fc_x2_multiply_conjugate_32fc(tmp, samples+1, samples, max)
	float out[max]; 
	for(i=0; i<max; i++) {
		tmp[i].I = samples[i].I*samples[i+1].I + samples[i].Q*samples[i+1].Q;
		tmp[i].Q = samples[i+1].I*samples[i].Q - samples[i].I*samples[i+1].Q;
	}
	// demodulate
	for(i=0; i<max; i++) {
		out[i] = atan2(tmp[i].Q, tmp[i].I);
	}

	// maybe some filtering here would not be bad? we'll see later
	//

	// clock recovery.
	// first, hard decision
	for(i=0; i<max-SAMPLE_PER_BIT; i++) {
		float bit=0;
		for(int j=0; j<SAMPLE_PER_BIT; j++) bit += out[i+j];
		procbit(bit<0);
	}
	return max-SAMPLE_PER_BIT;
}

#define PLLMAX 10000U
//#define PLLINC (PLLMAX/SAMPLE_PER_BIT-36)
#define PLLINC (PLLMAX/SAMPLE_PER_BIT)
#define INC (PLLINC / 32 * 2)

int procnone(int bit);
void prochead(int bit);
void procdata(int bit);

enum { RX_NONE, RX_HEAD, RX_DATA };
#define SYNCMASK 0x00FFFFFFU
#define SYNCFLAG 0x00557650U

int state=RX_NONE;
int pll=0;

int flag = 0;

#define OUTBUFSIZE 512
static unsigned char outbuf[OUTBUFSIZE];
int outpos=0;

int pllinc = PLLINC;
#define PLLGAIN 80

#define PLLHISTLEN 64
int pllhistory[PLLHISTLEN];
int pllhisti=0;

int procbit(int bit) {
	static int prevbit = 0;
	if(bit != prevbit) { // && state==RX_NONE) {
		if(pll < PLLMAX/2U) { pll += INC; pllhistory[pllhisti]=INC;  }
		else { pll -= INC; pllhistory[pllhisti]=-INC; }
		pllhisti=(pllhisti+1)%PLLHISTLEN;
	}
	prevbit = bit;
	pll += pllinc;
	if(pll > PLLMAX) {
		if(flag) {
			int psum=0;
			for(int i=pllhisti; i<pllhisti+PLLHISTLEN-8; i++) {
				psum += pllhistory[i%PLLHISTLEN];
			}
			pllinc += psum/(PLLHISTLEN-8)/SAMPLE_PER_BIT;

			int i1 = pllinc - PLLINC;
			double diff = 100.0*(i1)/PLLINC;
			// TODO: find out why this is not working:
			//   (it threats pllinc-PLLINC as an unsigned 32bit int!?!?
			//double diff = 100.0*(pllinc-PLLINC)/PLLINC;
			fprintf(stderr," pllsum: %d  new pllinc: %d [Symbol clock error: %+2.2f\%]\n", psum/PLLHISTLEN, pllinc, diff);
		}
		char b = bit | flag;
		flag = 0;
		pll -= PLLMAX;
		if(state == RX_NONE) procnone(bit);
		else if (state==RX_HEAD) prochead(bit);
		else procdata(bit);
		outbuf[outpos++] = b;
		if(outpos>=OUTBUFSIZE) {
			write(output, outbuf, OUTBUFSIZE);
			outpos=0;
		}
	}
}

unsigned char headbits[660+16];
int nheadbits = 0;

uint32_t pattern;

int procnone(int bit) {
	pattern = (pattern<<1) | (bit&0x01);
	if((pattern&SYNCMASK)==SYNCFLAG) {
		fprintf(stderr,"\nSYNC detected");
		state = RX_HEAD;
		flag = 2;
		nheadbits=0;
	}
	return bit;
}

unsigned char head[41];
int bodylen;
unsigned char data[2000];
int datacount;
int datalen;


void prochead(int bit) {
	headbits[nheadbits] = bit&1;
	nheadbits++;
	if(nheadbits>=HEADBITS) {
		// decode header
		state = RX_DATA;
		unsigned char head[HEADBITS/8];
		int dlen = dstar_decode_head(headbits, head);
		dstar_printhead(head, dlen);
		if(dlen>1800) dlen=1800;
		datalen = (dlen+4)*8;
		datacount = 0;
	}
}

void writetap(unsigned char *data, int datalen) {
	// write to TAP device
	write(tapfd, data, datalen);
}

void procdata(int bit) {
	//bit=descramblebit(bit&0x1);
	if((datacount&7)==0) data[datacount>>3]=0;
	data[datacount>>3] |= (bit<<(datacount&7));
	datacount++;
	if(datacount>datalen) {
		unsigned char ethframe[datacount/8];
		dstar_decode_data(data, datacount/8, ethframe);
		writetap(ethframe, datacount/8);
		state = RX_NONE;
	}
}

// reads data from somewhere, processes, 
int mainrunner(char *file) {
	complexf buf[BLOCKSIZE];
	int infh;
	infh = open(file, O_RDONLY);
	if(infh<0) { perror(file); exit(1); }
	int pos = 0;
	while(1) {
		int n = read(infh, buf+pos, sizeof(complexf)*(BLOCKSIZE-pos));
		if(n<=0) break;
		n = n/sizeof(complexf); // # samples
		int out = procsamples(buf, n+pos);
		// we have consumed out samples; end of buffer is at pos+n
		memmove(buf, buf+out, sizeof(complexf)*(n+pos-out));
		pos = pos + n - out;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	dstar_init();
	char dev[]="dstar%d";
	tapfd = tap_init(dev);
	fprintf(stderr,"TAP device is ready: %s\n", dev);
	char startupcmd[128];
	snprintf(startupcmd, 128, "./startup-ws %s", dev);
	system(startupcmd);

	output = open ("outputc.dat", O_CREAT|O_TRUNC|O_WRONLY, 0644);
	if(output<0) { perror("outputc.dat"); exit(1); }
	mainrunner(argc>1?argv[1]:"input.cplx");
}

