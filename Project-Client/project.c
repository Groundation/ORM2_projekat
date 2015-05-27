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
#include <pthread.h>
#include "orm_types.h"

int packet_size = sizeof(eth_header) + sizeof(udp_header)+sizeof(ip_header)+sizeof(pkt_data); 

void PreparePacket(u_char *packet, char *data)
{
	eth_header* eh;
	ip_header* ih;
	udp_header* uh;
	pkt_data* pd;

	/*Ethernet header*/
	eh = (eth_header*) packet;
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
	ih = (ip_header *) (packet + sizeof(eth_header));
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
	uh = (udp_header*) (packet + sizeof(eth_header) + sizeof(ip_header));
	uh->dport = htons(50030);
	uh->sport = htons(50030);
	uh->len = htons(sizeof(udp_header) + sizeof(pkt_data));
	/*Packet Data*/
	pd = (pkt_data*) (packet + sizeof(eth_header) + sizeof(ip_header) + sizeof(udp_header));
	pd->seq = 1;
	pd->ack = 2;
	memcpy(pd->data, data, DATA_SIZE); //PROMENJENA LINIJA KODA!!! stajalo: strcpy
}

int main()
{
	pcap_if_t *alldevs; 
	pcap_if_t *d;
	int n;

	int inum;
	int i=0;
	int lenght;
	pcap_t *adhandle;
	struct pcap_pkthdr* pkt_header;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ip and udp and dst port 50030";
	struct bpf_program fcode;
	
	FILE *ptr_myfile;
	u_char buf[sizeof(eth_header) + sizeof(udp_header)+sizeof(ip_header)+sizeof(pkt_data)];
	char read_data[DATA_SIZE];
	
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
	
	ptr_myfile = fopen("test.txt","rb");
	if (!ptr_myfile)
	{
		printf("Unable to open file!");
		return 1;
	}

	for(i=0; i<3; i++)
	{
		fread(read_data, DATA_SIZE, 1, ptr_myfile);
		PreparePacket(buf, read_data);
		if (pcap_sendpacket(adhandle, buf, packet_size) != 0)
		{
			fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(adhandle));
			return;
		}
	}
	
	fclose(ptr_myfile);

	return 0;
}