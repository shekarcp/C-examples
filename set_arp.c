#include <stdio.h>
#include <stdint.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>


static int atoip(const char *str, uint32_t *ip) 
{
	unsigned a, b, c, d;

	if(sscanf(str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4 || a > 255 || b > 255 || c > 255 || d > 255)
		return 1;

	*ip = a * 0x1000000 + b * 0x10000 + c * 0x100 + d;

	printf("converted IP : %x", *ip);
	return 0;
}

int atomac(unsigned char macAddr[6], char *str) {

	unsigned mac[6];

	if(sscanf(str, "%2x:%2x:%2x:%2x:%2x:%2x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], 
	   &mac[5] ) != 6)
		return 1;

	int i;
	for(i=0; i < 6; i++) {
		if (mac[i] > 0xff)
			return 1;
		macAddr[i] = (unsigned char) mac[i];
	}

	return 0;

}

int kernel_set_arp(uint32_t ip, unsigned char *mac) 
{

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0 )
		return 1;
	
	struct arpreq req;
	memset(&req, 0, sizeof(req));
	req.arp_ha.sa_family = ARPHRD_ETHER;
	memcpy(&req.arp_ha.sa_data, mac, 6);
	req.arp_flags = ATF_PERM, ATF_COM;

	struct sockaddr_in *in = (struct sockaddr_in*) &req.arp_pa;
	in->sin_addr.s_addr = htonl(ip);
	in->sin_family = AF_INET;

	if(ioctl(fd, SIOCSARP, &req) < 0) {
		close(fd);
		return 1;
	}

	return 0;



}


int main(int argc, char **argv)
{

	uint32_t ip;
	if(atoip(argv[1], &ip)) {
		printf("Invalid IP address\n");
		return -1;
	}

	uint8_t mac[6];
	if (atomac(mac, argv[2])) {
		printf("Invalid mac address\n");
		return -1;

	}
	if(kernel_set_arp(ip, mac)) {
		printf("Arp entry not active\n");
	}

	return 0;

}
