// RT-RK
// Osnovi Racunarskih Mreza 2
// File name: project.c

#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>
 
#define DATA_SIZE 8

/* Packet header and data */
typedef struct pkt_data
{
	u_int seq;
	u_int ack;
	char data[DATA_SIZE];
}pkt_data;

/* 4 bytes IP address */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
}ip_header;

/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

/* Ethernet header */
typedef struct eth_header
{
	u_char dest[6];
	u_char source[6];
	u_char eth_type[2];
}eth_header;

int packet_size = sizeof(eth_header) + sizeof(udp_header)+sizeof(ip_header)+sizeof(pkt_data); 

void PreparePacket(u_char **packet, char *data)
{
	eth_header* eh;
	ip_header* ih;
	udp_header* uh;
	pkt_data* pd;

	*packet = (u_char*) malloc(packet_size);
	/*Ethernet header*/
	eh = (eth_header*) *packet;
	eh->source[0] = 0x00;
	eh->source[1] = 0x19;
	eh->source[2] = 0x99;
	eh->source[3] = 0xd2;
	eh->source[4] = 0xb3;
	eh->source[5] = 0x8f;
	eh->dest[0] = 0x00;
	eh->dest[1] = 0x19;
	eh->dest[2] = 0x99;
	eh->dest[3] = 0xd3;
	eh->dest[4] = 0x94;
	eh->dest[5] = 0xa0;
	eh->eth_type[0] = 0x08;
	eh->eth_type[1] = 0x00;
	/*IP header*/
	ih = (ip_header *) (*packet + sizeof(eth_header));
	ih->ver_ihl = 0x45;									// Version (4 bits) + Internet header length (4 bits)
	ih->tos = 0;										// Type of service 
	ih->tlen = htons(packet_size - sizeof(eth_header));	// Total length
	ih->flags_fo = 0;									// Flags (3 bits) + Fragment offset (13 bits)
	ih->ttl = 128;										// Time to live
	ih->proto = 17;										// Protocol

	ih->saddr.byte1 = 192;
	ih->saddr.byte2 = 168;
	ih->saddr.byte3 = 32;
	ih->saddr.byte4 = 64;
	ih->daddr.byte1 = 192;
	ih->daddr.byte2 = 168;
	ih->daddr.byte3 = 32;
	ih->daddr.byte4 = 52;
	/*UDP header*/
	uh = (udp_header*) (*packet + sizeof(eth_header) + sizeof(ip_header));
	uh->dport = htons(50030);
	uh->sport = htons(50030);
	uh->len = htons(sizeof(udp_header) + sizeof(pkt_data));
	/*Packet Data*/
	pd = (pkt_data*) (*packet + sizeof(eth_header) + sizeof(ip_header) + sizeof(udp_header));
	pd->seq = 1;
	pd->ack = 2;
	strcpy(pd->data,data);
}

int main()
{
	pcap_if_t *alldevs; 
	pcap_if_t *d;
	int n;

	/**
	pcap_if_t -> instance of pcap_if structure; fields :
	{
		struct pcap_if *next;			// pointer to next element in list
		char *name;						// name to hand to "pcap_open_live()" 
		char *description;				//textual description to user interface
		struct pcap_addr *addresses;	//pointer, to the 1st el. of list of addresses for interface
		bpf_u_int32 flags;				// PCAP_IF_ interface flags
	}
	
	**/

	int inum;
	int i=0;
	int lenght;
	pcap_t *adhandle;
	struct pcap_pkthdr* pkt_header;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ip and udp and dst port 50030";
	struct bpf_program fcode;
	u_char* buf;
	char data[8];
	strcpy(data, "test123");
	
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	
	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);
	
	/* Check if the user specified a valid adapter */
	if(inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");
		
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the adapter */
	if ((adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	PreparePacket(&buf,data);
	if (pcap_sendpacket(adhandle, buf, packet_size) != 0)
    {
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(adhandle));
        return;
    }
	return 0;
}