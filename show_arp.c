#include <stdio.h>

#define LINE_BUF 1024
int showArp()
{


	FILE *fp = fopen("/proc/net/arp", "r");
	if (fp == NULL) {
		printf("ARP entry not found\n");
		return -1;
	}

	char line[LINE_BUF +1];
	if(fgets(line, LINE_BUF, fp) == NULL) {
		printf("Arp information not available\n");
		return -1;
	}

	while (fgets(line, LINE_BUF, fp)) {

		char ipstr[32];
		unsigned int type;
		unsigned int flags;
		int rv = sscanf(line, "%s 0x%x 0x%x", ipstr, &type, &flags);
		if (rv != 3) {
			break;
		}

		printf("%s", line);

	}

	fclose(fp);

	return 0;
}


int main()
{

	showArp();
	return 0;
}
