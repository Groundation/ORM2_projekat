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

#include "pcap.h"
#include "pthreadVC2\pthread.h"
#include "pthreadVC2\semaphore.h"

#define DATA_SIZE 8
#define ETH_LEN 14
#define IP_LEN 20
#define UDP_LEN 8
#define TOT_LEN ETH_LEN + IP_LEN + UDP_LEN

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

/* UDP header */
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

/* ETH header */
typedef struct eth_header
{
	u_char eth_dhost[6];		//Destination host address
	u_char eth_shost[6];		//Source host address
	u_char eth_type[2];			//IP? ARP? RARP? etc
}eth_header;

/* PKT data */
typedef struct pkt_data
{
	u_int seq_num;
	u_int ack;
	u_char data[DATA_SIZE];
}pkt_data;

/* prototype of the packet handler */
void PacketHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt);
/* prototype of the buffering thread */
void* Buffering(void* param);
/* prototype of writing file thread */
void* Writing(void* param);

static sem_t pkt_arrived;
static pthread_t thr;

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ip and udp port 50030";
	struct bpf_program fcode;
	
	sem_init(&pkt_arrived, 0, 0); 
	pthread_create(&thr, NULL, Buffering, NULL);
	
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
	
	/* Check the link layer. We support only Ethernet for simplicity. */
	if(pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	if(d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask=0xffffff; 


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
	{
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	//set the filter
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr,"\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	printf("\nlistening on %s...\n", d->description);
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	
	/* start the capture */
	pcap_loop(adhandle, 0, PacketHandler, NULL);
	
	return 0;
}

void* Buffering(void* param)
{
	while(1)
	{
		sem_wait(&pkt_arrived);
		printf("dobio paket\n");
	}
}

void* Writing(void* param)
{
	return NULL;
}

/* Callback function invoked by libpcap for every incoming packet */
void PacketHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt)
{
	ip_header *ih;
	udp_header *uh;
	eth_header *eh;
	pkt_data *pd;
	u_short sport,dport;
	FILE* fd = NULL;

	/*
	 * unused parameter
	 */
	(VOID)(param);
	
	/* notify buffering thread that packet arrived */
	sem_post(&pkt_arrived);
	
	/* open file for writing in addition mode */
	fd = fopen("test.bin", "a");

	/* retrieve the position of the ETH header */
	eh = (eth_header *) pkt;

	/* retireve the position of the IP header */
	ih = (ip_header *) (pkt + ETH_LEN); //length of ethernet header

	/* retireve the position of the UDP header */
	uh = (udp_header *) ((u_char*)ih + IP_LEN);

	/* retrieve the position of the packet data */
	pd = (pkt_data *) ((u_char*)uh + UDP_LEN);
	
	/* write to file data from pkt_data structure */
	fwrite(pd->data, 1, DATA_SIZE, fd);
	
	/* close file */
	fclose(fd);

	/* convert from network byte order to host byte order */
	sport = ntohs(uh->sport);
	dport = ntohs(uh->dport);

	/* print ip addresses and udp ports */
	printf("\nIP adresses: %d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		sport,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dport);

	printf("\nPacket data:\nACK: %d\nSequence_number: %d\nClear data: %s\n\n",
		pd->ack,
		pd->seq_num,
		pd->data);

	/*printf("\nVer_ihl: %x\nTos: %d\nTlen: %d\nId: %d\nFlags_fo: %d\nTTL: %d\nProto: %d\nCRC: %d\nOp_pad: %x\n\n",
		ih->ver_ihl,
		ih->tos,
		htons(ih->tlen),
		ih->identification,
		ih->flags_fo,
		ih->ttl,
		ih->proto,
		ih->crc,
		ih->op_pad);

	eh = (eth_header *) pkt_data;
	printf("MAC adresses: %x-%x-%x-%x-%x-%x -> %x-%x-%x-%x-%x, %x\n",
		eh->eth_shost[0],
		eh->eth_shost[1],
		eh->eth_shost[2],
		eh->eth_shost[3],
		eh->eth_shost[4],
		eh->eth_shost[5],
		eh->eth_dhost[0],
		eh->eth_dhost[1],
		eh->eth_dhost[2],
		eh->eth_dhost[3],
		eh->eth_dhost[4],
		eh->eth_dhost[5],
		eh->eth_type
		);*/
}
