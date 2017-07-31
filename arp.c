// Developer : ming
// platform : Ubuntu 16.04.2
// Reference : https://stackoverflow.com/questions/6767296/how-to-get-local-ip-and-mac-address-c

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>

void get_mac(unsigned char MAC_str[13])
{
	#define HWADDR_len 6
	int s,i;
	struct ifreq ifr;
	
	s = socket(AF_INET, SOCK_DGRAM, 0);
	strcpy(ifr.ifr_name, "ens33");
	ioctl(s, SIOCGIFHWADDR, &ifr);
	for (i=0; i<HWADDR_len; i++)
		sprintf(&MAC_str[i*2],"%02X",((unsigned char*)ifr.ifr_hwaddr.sa_data)[i]);
	MAC_str[12]='\0';
}

int main(int argc, char *argv[])
{
	unsigned char mac[13];
	int i;

	get_mac(mac);
	puts(mac);

return 0;
}
