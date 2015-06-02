#include "proto.h"
#include <windows.h>

void* Buffering(void* param)
{
	while(1)
	{
		
	}
}

void* Writing(void* param)
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
}

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
	
	/* retrieve the position of the packet data */
	pd = (pkt_data *) (pkt + (TOT_LEN - DAT_LEN));

	/* save ack of this packet */
	current_ack = pd->ack;

	/* PREPARE PACKET FOR SENDING ACK */
	
	/* Ethernet header */
	eh = (eth_header*) pkt;

	/* IP header */
	ih = (ip_header*) (pkt + ETH_LEN);

	uh = (udp_header*) ((u_char*) ih + IP_LEN);

	/* Switch MAC adresses */
	temp_eth = eh->daddr;
	eh->daddr = eh->saddr;
	eh->saddr = temp_eth;
	
	/* Switch IP adresses */
	temp_ip = ih->daddr;
	ih->daddr = ih->saddr;
	ih->saddr = temp_ip;

	//printf("PRE sport: %d, dport: %d\n", htons(uh->sport), htons(uh->dport));
	/* Switch UDP ports */
	temp_port = uh->dport;
	uh->dport = uh->sport;
	uh->sport = htons(32000);
	//printf("POSLE sport: %d, dport: %d\n", htons(uh->sport), htons(uh->dport));

	pd->ack = (pd->seq + 1);

	/* SEND ACK */
	//printf("saljem ack\n");
	if(pcap_sendpacket(adhandle, pkt, TOT_LEN) != 0)
	{
		fprintf(stderr, "\nError sending ACK packet: %s\n", pcap_geterr(adhandle));
	}

	/* WRITE USER DATA TO FILE */
	if(pd->seq >= 0)
	{
		fwrite(pd->data, 1, DATA_SIZE, fd);
	}
	else if(pd->seq == LAST_SEQ) //last packet arrived
	{
		fwrite(pd->data, 1, current_ack, fd); //current_ack is number of useful bytes
		last_pkt = TRUE;
	}

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