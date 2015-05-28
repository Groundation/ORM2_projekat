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

//int packet_size = sizeof(eth_header) + sizeof(udp_header)+sizeof(ip_header)+sizeof(pkt_data); 

void PreparePacket(u_char *packet, char *data, int seq, int bytes)
{
	eth_header* eh;
	ip_header* ih;
	udp_header* uh;
	pkt_data* pd;

	/*Ethernet header*/
	eh = (eth_header*) packet;
	eh->source[0] = 0xa0;
	eh->source[1] = 0x48;
	eh->source[2] = 0x1c;
	eh->source[3] = 0x8a;
	eh->source[4] = 0x1e;
	eh->source[5] = 0xee;
	eh->dest[0] = 0xa0;
	eh->dest[1] = 0x48;
	eh->dest[2] = 0x1c;
	eh->dest[3] = 0x8c;
	eh->dest[4] = 0x1e;
	eh->dest[5] = 0x96;
	eh->eth_type[0] = 0x08;
	eh->eth_type[1] = 0x00;
	/*IP header*/
	ih = (ip_header *) (packet + sizeof(eth_header));
	ih->ver_ihl = 0x45;									// Version (4 bits) + Internet header length (4 bits)
	ih->tos = 0;										// Type of service 
	ih->tlen = htons(TOTAL_LENGTH - sizeof(eth_header));	// Total length
	ih->flags_fo = 0;									// Flags (3 bits) + Fragment offset (13 bits)
	ih->ttl = 128;										// Time to live
	ih->proto = 17;										// Protocol

	ih->saddr.byte1 = 192;
	ih->saddr.byte2 = 168;
	ih->saddr.byte3 = 30;
	ih->saddr.byte4 = 55;
	ih->daddr.byte1 = 192;
	ih->daddr.byte2 = 168;
	ih->daddr.byte3 = 30;
	ih->daddr.byte4 = 71;
	/*UDP header*/
	uh = (udp_header*) (packet + sizeof(eth_header) + sizeof(ip_header));
	uh->dport = htons(50030);
	uh->sport = htons(50030);
	uh->len = htons(sizeof(udp_header) + sizeof(pkt_data));
	/*Packet Data*/
	pd = (pkt_data*) (packet + sizeof(eth_header) + sizeof(ip_header) + sizeof(udp_header));
	pd->seq = seq;
	pd->ack = bytes;
	memset(pd->data, 0, DATA_SIZE);
	memcpy(pd->data, data, DATA_SIZE); //PROMENJENA LINIJA KODA!!! stajalo: strcpy
}

int main()
{
	pcap_if_t *alldevs; 
	pcap_if_t *d;
	pkt_data* pd;
	int n;
	int num_of_read_bytes = 0;
	int seq = 0;

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

	while(1)
	{
		num_of_read_bytes = fread(read_data, 1, DATA_SIZE, ptr_myfile);
		if(num_of_read_bytes < DATA_SIZE)
		{
			PreparePacket(buf, read_data, -1, num_of_read_bytes);
			if (pcap_sendpacket(adhandle, buf, TOTAL_LENGTH) != 0)
			{
				fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(adhandle));
				return;
			}
			break;
		} else
		{ 
			PreparePacket(buf, read_data, seq, 0);
			seq++;
			if (pcap_sendpacket(adhandle, buf, TOTAL_LENGTH) != 0)
			{
				fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(adhandle));
				return;
			}
		}
	}

	fclose(ptr_myfile);

	return 0;
}