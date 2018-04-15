#include <sys/ioctl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <unistd.h>

int tap_init(char *name) {
	int tap;
	struct ifreq ifr;

	tap = open("/dev/net/tun", O_RDWR);
	if(tap<0) { perror("/dev/net/tun"); return -1; }

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP|IFF_NO_PI;
	strncpy(ifr.ifr_name, name, IFNAMSIZ);
	int itap = ioctl(tap, TUNSETIFF, (void *)&ifr);
	if(itap<0) { perror("TUNSETIFF"); close(tap); return -1; }

	strcpy(name, ifr.ifr_name);
	return tap;
}


