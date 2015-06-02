#include "proto.h"
#include <windows.h>

void* Buffering(void* param)
{
	while(1)
	{
		
	}
}

/*void* Writing(void* param)
{
	while(1)
	{	
		sem_wait(&pkt_arrived);
		while(more_pkts)
		{
			pthread_mutex_lock(&mtx);
			more_pkts--;
			pthread_mutex_unlock(&mtx);
			 
			if(last_pkt && !more_pkts)
			{
				printf("useful bytes: %d\n, seq: %d", fwrite(buf_rcv[seq], 1, useful_bytes, fd), seq);
				wr_end = TRUE;
			}
			else
			{
				fwrite(buf_rcv[seq], 1, DATA_SIZE, fd);
			}
			seq++;
		}

		if(wr_end)
			break;
	}
}*/

/* function called for every incoming packet */
void PacketHandler(pcap_t* adhandle, u_char *pkt, FILE* file_p)
{
	int current_ack = 0;

	eth_header* eh;
	ip_header* ih;
	udp_header* uh;
	mac_address temp_eth;
	ip_address temp_ip;
	int temp_port; 

	pd = (pkt_data *) (pkt + (TOT_LEN - DAT_LEN));
	
	if(pd->seq < 0)	//last pkt arrived
		current_ack = pd->ack;

	/* PREPARE PACKET FOR SENDING ACK */

	/* Ethernet header */
	eh = (eth_header*) pkt;

	/* IP header */
	ih = (ip_header*) (pkt + ETH_LEN);

	/* UDP header */
	uh = (udp_header*) ((u_char*) ih + IP_LEN);

	/* Switch MAC adresses */
	temp_eth = eh->daddr;
	eh->daddr = eh->saddr;
	eh->saddr = temp_eth;
	
	/* Switch IP adresses */
	temp_ip = ih->daddr;
	ih->daddr = ih->saddr;
	ih->saddr = temp_ip;

	/* Switch UDP ports */
	temp_port = uh->dport;
	uh->dport = uh->sport;
	uh->sport = temp_port;

	pd->ack = (pd->seq + 1);

	/* SEND ACK */
	if(pcap_sendpacket(adhandle, pkt, TOT_LEN) != 0)
	{
		fprintf(stderr, "\nError sending ACK packet: %s\n", pcap_geterr(adhandle));
	}

	/* WRITE USER DATA TO FILE */
	if(pd->seq == (previous_seq + 1))
	{
		fwrite(pd->data, 1, DATA_SIZE, file_p);
	}
	else if(pd->seq < 0) //last packet arrived
	{
		fwrite(pd->data, 1, current_ack, file_p); //pd->ack is number of useful bytes
		last_pkt = TRUE;
	}

	previous_seq = pd->seq;

	/*if(pd->seq >= 0)
	{
		//memcpy(buf_rcv[pd->seq], pd->data, DATA_SIZE);
		printf("buf_rcv - ph: %s\n", buf_rcv[pd->seq]);
	}
	else if(pd->seq == LAST_SEQ)
	{
		//printf("last_seq\n");
		last_pkt = TRUE;
		useful_bytes = pd->ack;
	}

	pthread_mutex_lock(&mtx);
	more_pkts++;
	//printf("more_pkts - ph: %d\n", more_pkts);
	pthread_mutex_unlock(&mtx);

	if((more_pkts - 1) == 0)
		sem_post(&pkt_arrived);
		*/
}

pcap_t* SelectAndOpenDevice()
{
	/* buffer needed in case of error while searching devices */
	char errbuf[PCAP_ERRBUF_SIZE];
	
	/* temp numeric variables */
	int i = 0;
	int inum = 0;

	/* return value */
	pcap_t* ret_adhandle;

	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == ERROR)
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
		return NULL;
	}
	
	//printf("Enter the interface number (1-%d):",i);
	//scanf("%d", &inum);
	inum = 1;

	/* Check if the user specified a valid adapter */
	if(inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");
		
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return NULL;
	}

	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the adapter */
	if ((ret_adhandle = pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1,				// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return NULL;
	}

	return ret_adhandle;
}

int CompileAndSetFilter(pcap_t* adhandle)
{
	char packet_filter[] = "ip and udp and dst port 50030";
	struct bpf_program fcode;
	struct pcap_pkthdr *header;
	u_int netmask;
	
	/* Check the link layer. We support only Ethernet for simplicity. */
	if(pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return ERROR;
	}
	
	if(d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask=0xffffff; 

	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return ERROR;
	}
	
	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return ERROR;
	}
	
	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr,"\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return ERROR;
	}

	printf("\nlistening on %s...\n", d->description);
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	return 0;
}