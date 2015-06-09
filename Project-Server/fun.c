#ifndef FUN_C_INCLUDED
#define FUN_C_INCLUDED

#include "fun.h"
#include <windows.h>

void* AdapterThread(void* param)
{
	/* temp variables needed for pcap_next_ex */
	int res;
	struct pcap_pkthdr* header;

	/* handler of opened device */
	pcap_t *adhandle;

	/* packet buffer */
	u_char* pkt;
	u_char ack_pkt[TOT_LEN - DAT_LEN + 4];

	/* true only before first packet arrives so we can init ACK packet */
	u_char first_pkt = TRUE;

	DWORD start, end;

	int i = (int) param;

	pthread_mutex_lock(&mtx);
	adhandle = SelectAndOpenDevice();
	if(CompileAndSetFilter(adhandle) == ERROR)
		printf("Error setting filter\n");
	pthread_mutex_unlock(&mtx);
	
	start = GetTickCount(); 

	/* Retrieve the packets */
    while((res = pcap_next_ex(adhandle, &header, &pkt)) >= 0)
	{
		if(res == 0) //read timeout
		{
			//if(++n == TMOUT)
				//break;
			if((last_pkt && (num_pkts >= total_num_pkts)))
					break;	
			
			//printf("timeout, id: %d\n", i);
			continue;
		}
		//n = 0; //reset timeout counter

		/* Send ACK and write user data to file*/
		PacketHandler(adhandle, pkt, ack_pkt, first_pkt, i);
		
		if(end_thr[i] || (last_pkt && (num_pkts >= total_num_pkts)))
			break;	
    }

	end = GetTickCount();

	pthread_mutex_lock(&terminal);
	printf("running time: %d msec\n, thread: %d\n", (end - start), i);
	pthread_mutex_unlock(&terminal);
	
	return 0;
}

/* function called for every incoming packet */
void PacketHandler(pcap_t* adhandle, u_char *pkt, u_char *ack_pkt, u_char first_pkt, int id)
{
	int current_ack = 0;

	eth_header* eh;
	ip_header* ih;
	udp_header* uh;
	pkt_data* pd;		//points to data stuff in incoming packet
	pkt_data* ack_pd;	//points to data stuff in ack packet

	mac_address temp_eth;
	ip_address temp_ip;
	int temp_port;

	pd = (pkt_data *) (pkt + (TOT_LEN - DAT_LEN));

	pthread_mutex_lock(&mtx);
	++num_pkts;
	printf("seq num of packet: %d\nid: %d\nnum pkts: %d\n\n", pd->seq, id, num_pkts);
	if(last_pkt && (num_pkts == total_num_pkts))
		end_thr[id] = TRUE;
	pthread_mutex_unlock(&mtx);

	if(pd->seq < 0)	//last pkt arrived
		current_ack = pd->ack;
	
	/* PREPARE PACKET FOR SENDING ACK */

	if(first_pkt)
	{
		first_pkt = FALSE;

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

		ih->tlen = ih->tlen - DAT_LEN + 4;
	
		/* Switch UDP ports */
		temp_port = uh->dport;
		uh->dport = uh->sport;
		uh->sport = temp_port;

		uh->len = uh->len - DAT_LEN + 4;
		
		memcpy(ack_pkt, pkt, TOT_LEN - DAT_LEN + 4);
	}

	ack_pd = (pkt_data *) (ack_pkt + (TOT_LEN - DAT_LEN));
	ack_pd->ack = (pd->seq + 1);

	/* SEND ACK */
	if(pcap_sendpacket(adhandle, ack_pkt, TOT_LEN - DAT_LEN + 4) != 0)
	{
		fprintf(stderr, "\nError sending ACK packet: %s\n", pcap_geterr(adhandle));
	}

	/* WRITE USER DATA TO FILE */
	if(pd->seq >= 0)	//last packet hasn't arrived
	{
		pthread_mutex_lock(&file);
		fseek(fd, DATA_SIZE*pd->seq, SEEK_SET);
		fwrite(pd->data, 1, DATA_SIZE, fd);
		pthread_mutex_unlock(&file);
	}
	else if(pd->seq < 0) //last packet arrived
	{
		pthread_mutex_lock(&file);
		fseek(fd, DATA_SIZE*(-(pd->seq)), SEEK_SET);
		fwrite(pd->data, 1, current_ack, fd); //current ack is number of useful bytes
		pthread_mutex_unlock(&file);

		pthread_mutex_lock(&mtx);
		last_pkt = TRUE;
		total_num_pkts = (-pd->seq) + 1;
		pthread_mutex_unlock(&mtx);
	}

	previous_seq = pd->seq;
}

void FindAllDevices()
{
	/* Buffer needed in case of error while searching devices */
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == ERROR)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++num_inter, d->name);
		if (d->description)
			printf("(%s)\n", d->description);
		else
			printf("(No description available)\n");
	}
}

pcap_t* SelectAndOpenDevice()
{
	/* Buffer needed in case of error while searching devices */
	char errbuf[PCAP_ERRBUF_SIZE];
	
	/* Temp numeric variables */
	int	i = 0;
	int	inum = 0;

	/* Return value */
	pcap_t	*ret_adhandle = NULL;
	
	printf("Enter the interface number (1-%d):", num_inter);
	scanf("%d", &inum);

	/* Check if the user specified a valid adapter */
	if(inum < 1 || inum > num_inter)
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

	return 0;
}
#endif