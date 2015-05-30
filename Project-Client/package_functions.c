#include "package_functions.h"

void PreparePacket(u_char *packet, char *data, int seq, int bytes)
{
	eth_header_struct	*eh_ptr;
	ip_header_struct	*ih_ptr;
	udp_header_struct	*uh_ptr;
	pkt_data_struct		*pd_ptr;

	/* Ethernet header */
	eh_ptr				= (eth_header_struct*) packet;
	/* Destination address */
	eh_ptr->daddr.byte1 = 0x00;
	eh_ptr->daddr.byte2 = 0x19;
	eh_ptr->daddr.byte3 = 0x99;
	eh_ptr->daddr.byte4 = 0xD2;
	eh_ptr->daddr.byte5 = 0xB2;
	eh_ptr->daddr.byte6 = 0xF5;
	/* Source address */
	eh_ptr->saddr.byte1 = 0x00;
	eh_ptr->saddr.byte2 = 0x19;
	eh_ptr->saddr.byte3 = 0x99;
	eh_ptr->saddr.byte4 = 0xD3;
	eh_ptr->saddr.byte5 = 0x95;
	eh_ptr->saddr.byte6 = 0xFD;
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
	ih_ptr->saddr.byte1 = 192;
	ih_ptr->saddr.byte2 = 168;
	ih_ptr->saddr.byte3 = 32;
	ih_ptr->saddr.byte4 = 60;
	/* Destination address */
	ih_ptr->daddr.byte1 = 192;
	ih_ptr->daddr.byte2 = 168;
	ih_ptr->daddr.byte3 = 32;
	ih_ptr->daddr.byte4 = 63;

	/*UDP header*/
	uh_ptr			= (udp_header_struct*) ((u_char*)ih_ptr + IPH_LEN);
	uh_ptr->dport	= htons(50030);				// Destination Port
	uh_ptr->sport	= htons(50020);				// Source Port
	uh_ptr->len		= htons(UDP_LEN + DAT_LEN);	// Length of UPD + DATA
	/*Packet Data*/
	pd_ptr			= (pkt_data_struct*) ((u_char*)uh_ptr + UDP_LEN);
	pd_ptr->seq		= seq;
	pd_ptr->ack		= bytes;
	memset(pd_ptr->data,	0,	DATA_SIZE);
	memcpy(pd_ptr->data, data,	DATA_SIZE);
}

