#ifndef PACKAGE_FUNCTIONS_C_INCLUDED
#define PACKAGE_FUNCTIONS_C_INCLUDED

#include "package_functions.h"

void InitPackets(u_char *packet, mac_address_struct daddr, mac_address_struct saddr)
{
	eth_header_struct	*eh_ptr;
	ip_header_struct	*ih_ptr;
	udp_header_struct	*uh_ptr;

	/* Ethernet header */
	eh_ptr				= (eth_header_struct*) packet;
	/* Destination address */
	eh_ptr->daddr = daddr;
	/* Source address */
	eh_ptr->saddr = saddr;
	/* Ethernet type */
	eh_ptr->eth_type[0] = 0x08;	// Internet Protocol version 4
	eh_ptr->eth_type[1] = 0x00;

	/* IP header */
	ih_ptr				= (ip_header_struct *) (packet + ETH_LEN);
	ih_ptr->ver_ihl		= 0x45;						// Version (4 bits) + Internet header length (4 bits)
	ih_ptr->tos			= 0;						// Type of service 
	ih_ptr->tlen		= htons(TOT_LEN - ETH_LEN);	// Total length
	ih_ptr->flags_fo	= 0;						// Flags (3 bits) + Fragment offset (13 bits)
	ih_ptr->ttl			= 128;						// Time to live
	ih_ptr->proto		= 17;						// Protocol
	/* Source address */
	ih_ptr->saddr.byte1 = 0;
	ih_ptr->saddr.byte2 = 0;
	ih_ptr->saddr.byte3 = 0;
	ih_ptr->saddr.byte4 = 0;
	/* Destination address */
	ih_ptr->daddr.byte1 = 0;
	ih_ptr->daddr.byte2 = 0;
	ih_ptr->daddr.byte3 = 0;
	ih_ptr->daddr.byte4 = 0;

	/*UDP header*/
	uh_ptr			= (udp_header_struct*) ((u_char*)ih_ptr + IPH_LEN);
	uh_ptr->dport	= htons(50030);				// Destination Port
	uh_ptr->sport	= htons(60030);				// Source Port
	uh_ptr->len		= htons(UDP_LEN + DAT_LEN);	// Length of UPD + DATA
}

void PrepareData(u_char *packet, u_char *data, int seq, int bytes)
{
	pkt_data_struct		*pd_ptr;

	/*Packet Data*/
	pd_ptr			= (pkt_data_struct*) (packet + TOT_LEN - DAT_LEN);
	pd_ptr->seq		= seq;
	pd_ptr->ack		= bytes;
	memset(pd_ptr->data,	0,	DATA_SIZE);
	memcpy(pd_ptr->data, data,	DATA_SIZE);
}

int FillPacket(u_char *buffer,int *ex_ack)
{
	u_char data[DATA_SIZE];
	int num_of_read_bytes	= 0;

	pthread_mutex_lock(&file_mutx);
	if(last_pkt)
	{
		pthread_mutex_unlock(&file_mutx);
		return 1;
	}
	num_of_read_bytes = fread(data, 1, DATA_SIZE, file_ptr);
	if(num_of_read_bytes < DATA_SIZE)
	{
		seq = -seq;
		last_pkt = 1;
	}
	PrepareData(buffer, data, seq, num_of_read_bytes);
	printf("\nSeq: %d\n", seq);
	*ex_ack = ++seq;
	pthread_mutex_unlock(&file_mutx);
	return 0;
}

void SetupMacAdress()
{
	/* Wifi destination address*/
	wif_dmac.byte1 = 0x00;
	wif_dmac.byte2 = 0x0e;
	wif_dmac.byte3 = 0x8e;
	wif_dmac.byte4 = 0x61;
	wif_dmac.byte5 = 0xbb;
	wif_dmac.byte6 = 0x7b;
	/* wifi source address */
	wif_smac.byte1 = 0x00;
	wif_smac.byte2 = 0x0e;
	wif_smac.byte3 = 0x8e;
	wif_smac.byte4 = 0x45;
	wif_smac.byte5 = 0xb4;
	wif_smac.byte6 = 0xa4;
	/* Ethernet destination address*/
	eth_dmac.byte1 = 0x00;
	eth_dmac.byte2 = 0x19;
	eth_dmac.byte3 = 0x99;
	eth_dmac.byte4 = 0xd3;
	eth_dmac.byte5 = 0x94;
	eth_dmac.byte6 = 0xa0;
	/* Ethernet source address */
	eth_smac.byte1 = 0x00;
	eth_smac.byte2 = 0x19;
	eth_smac.byte3 = 0x99;
	eth_smac.byte4 = 0xd2;
	eth_smac.byte5 = 0xb3;
	eth_smac.byte6 = 0x8f;
}

#endif /* PACKAGE_FUNCTIONS_C_INCLUDED */