// Developer: ming
// platform: Ubuntu 16.04.2
// Reference : http://www.binarytides.com/c-program-to-get-ip-address-from-interface-name-on-linux/
// Reference : http://www.programming-pcap.aldabaknocking.com/code/arpsniffer.c

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h> // ifreq
#include <unistd.h> // close
#include <arpa/inet.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>

/* ARP Header, (assuming Ethernet+IPv4)            */ 
#define ARP_REQUEST 1   /* ARP Request             */ 
#define ARP_REPLY 2     /* ARP Reply               */ 

//typedef struct arphdr { 
//    u_int16_t htype;    /* Hardware Type           */ 
//    u_int16_t ptype;    /* Protocol Type           */ 
//    u_char hlen;        /* Hardware Address Length */ 
//    u_char plen;        /* Protocol Address Length */ 
//    u_int16_t oper;     /* Operation Code          */ 
//    u_char sha[6];      /* Sender hardware address */ 
//    u_char spa[4];      /* Sender IP address       */ 
//    u_char tha[6];      /* Target hardware address */ 
//    u_char tpa[4];      /* Target IP address       */ 
//}arphdr_t; 

int main(int argc, char *argv[])
{
	int fd;
	struct ifreq ifr;
	unsigned char *mac;
	char *dev, *sender_ip, *target_ip;
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];

	struct ether_header *ethhdr;
	char packet[100];

	if (argc != 4) {
		printf("input needed: 1. dev 2. sender_ip 3. target_ip \n");
		exit(1);
	}

	dev = argv[1];
	sender_ip = argv[2];
	target_ip = argv[3];

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	/* Type of address to retrieve - IPv4 IP address */
	ifr.ifr_addr.sa_family = AF_INET;
	/* Copy the interface name in the ifreq structure */
	strncpy(ifr.ifr_name , dev , IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);

	mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

	/* display mac address */
	printf("Mac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
 
	/* display result */
	printf("%s - %s\n" , dev , inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr) );

	/* Open network device for packet capture */ 
	if((handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf))==NULL) {
		printf("Couldn't open device %s : %s\n", dev, errbuf);
		return 2;
	}

	/* Ethernet packet */
	ethhdr = (struct ether_header *)packet;
	ethhdr->ether_type = ntohs(ETHERTYPE_ARP);
	for(int i=0;i<ETH_ALEN;i++) ethhdr->ether_dhost[i] = '\xff';
	for(int j=0;j<ETH_ALEN;j++) ethhdr->ether_shost[j] = mac[j];



	return 0;
}
