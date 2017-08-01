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
#include <net/if_arp.h>
#include <net/ethernet.h>

/* ARP Header, (assuming Ethernet+IPv4)                   */ 
#define ETHERNET 1
#define ARP_REQUEST 1          /* ARP Request             */ 
#define ARP_REPLY 2            /* ARP Reply               */ 
typedef struct arpheader { 
    uint16_t htype;            /* Hardware Type           */ 
    uint16_t ptype;            /* Protocol Type           */ 
    uint8_t hlen;              /* Hardware Address Length */ 
    uint8_t plen;      	       /* Protocol Address Length */ 
    uint16_t oper;	       /* Operation Code          */ 
    unsigned char sha[6];      /* Sender hardware address */ 
    uint32_t spa;              /* Sender IP address       */ 
    unsigned char tha[6];      /* Target hardware address */ 
    uint32_t tpa;              /* Target IP address       */ 
} __attribute__((packed)) arphdr_t; 

int main(int argc, char *argv[])
{
	int fd;
	struct ifreq ifr;
	unsigned char attacker_mac[6];
	uint32_t *attacker_ip;
	char *dev, *sender_ip, *target_ip;
	
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	int res;
	struct pcap_pkthdr *header;
	const u_char *reply_data;

	struct ether_header *ethhdr;
	char packet[100];

	arphdr_t *arpheader = NULL;

	if (argc != 4) {
		printf("input needed: <dev> <sender_ip> <target_ip> \n");
		exit(1);
	}

	dev = argv[1];
	sender_ip = argv[2];
	target_ip = argv[3];

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0) perror("socket fail");

	/* Type of address to retrieve - IPv4 IP address */
	//ifr.ifr_addr.sa_family = AF_INET;
	/* Copy the interface name in the ifreq structure */
	strncpy(ifr.ifr_name , dev , IFNAMSIZ-1);
	if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) perror("ioctl fail");
	close(fd);

	memcpy(attacker_mac, ifr.ifr_hwaddr.sa_data, 6);

	/* Display mac address */
	//printf("Mac : %s:%s:%s:%s:%s:%s\n" , attacker_mac[0], attacker_mac[1], attacker_mac[2], attacker_mac[3], attacker_mac[4], attacker_mac[5]);
 
	/* Display ip address */
	attacker_ip = ((struct sockaddr_in *)&ifr.ifr_addr )->sin_addr.s_addr;
	// printf("%s : %s\n" , dev , attacker_ip );
	//attacker_ip = (((struct sockaddr_in *)&ifr.ifr_addr )->sin_addr.s_addr);

	/* Open network device for packet capture */ 
	if((handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf))==NULL) {
		printf("Couldn't open device %s : %s\n", dev, errbuf);
		return 2;
	}

	/* Make Ethernet packet */
	ethhdr = (struct ether_header *)packet;
	ethhdr->ether_type = ntohs(ETHERTYPE_ARP);
	for(int i=0;i<ETH_ALEN;i++) ethhdr->ether_dhost[i] = '\xff';
	for(int j=0;j<ETH_ALEN;j++) ethhdr->ether_shost[j] = attacker_mac[j];
	
	/* Make ARP packet */
	arpheader = (struct arpheader *)(packet+14);
	arpheader->htype = ntohs(ETHERNET);
	arpheader->ptype = ntohs(ETHERTYPE_IP);
	arpheader->hlen = sizeof(arpheader->sha); 
	arpheader->plen = sizeof(arpheader->spa);
	arpheader->oper = ntohs(ARP_REQUEST);
	memcpy(arpheader->sha, attacker_mac, 6);
	arpheader->spa = attacker_ip;
	memcpy(arpheader->tha, "\x00\x00\x00\x00\x00\x00",6);
	arpheader->tpa = inet_addr(sender_ip);

	/* Send ARP request */
	pcap_sendpacket(handle, packet, 42);	
	/* int pcap_sendpacket(pcap_t *p, const u_char *buf, int size);
	 * sends a raw packet through the network interface.
	 * returns 0 on success and -1 on failure.
	 * If -1 is returned, pcap_geterr() or pcap_perror() may be called 
	 * with p as an argument to fetch or display the error text.
	 */

	/* Get ARP reply */
	while(1) {
		res = pcap_next_ex(handle, &header, &reply_data);
		if(res < 0) exit(1);
		else if(res == 0); //pcap_sendpacket(handle, packet, 42);	

	}	

	/* Close handle */
	pcap_close(handle);
	
	return 0;
}
