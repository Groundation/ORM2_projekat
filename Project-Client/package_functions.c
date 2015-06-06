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
	uh_ptr->sport	= htons(50020);				// Source Port
	uh_ptr->len		= htons(UDP_LEN + DAT_LEN);	// Length of UPD + DATA
}

void PreparePacket(u_char *packet, char *data, int seq, int bytes)
{
	pkt_data_struct		*pd_ptr;

	/*Packet Data*/
	pd_ptr			= (pkt_data_struct*) (packet + TOT_LEN - DAT_LEN);
	pd_ptr->seq		= seq;
	pd_ptr->ack		= bytes;
	memset(pd_ptr->data,	0,	DATA_SIZE);
	memcpy(pd_ptr->data, data,	DATA_SIZE);
}

void SetupMacAdress()
{
	/* Wifi destination address*/
	wif_dmac.byte1 = 0x00;
	wif_dmac.byte2 = 0x0e;
	wif_dmac.byte3 = 0x8e;
	wif_dmac.byte4 = 0x45;
	wif_dmac.byte5 = 0xb4;
	wif_dmac.byte6 = 0xa4;
	/* wifi source address */
	wif_smac.byte1 = 0x00;
	wif_smac.byte2 = 0x0e;
	wif_smac.byte3 = 0x8e;
	wif_smac.byte4 = 0x45;
	wif_smac.byte5 = 0xb4;
	wif_smac.byte6 = 0x56;
	/* Ethernet destination address*/
	eth_dmac.byte1 = 0xa0;
	eth_dmac.byte2 = 0x48;
	eth_dmac.byte3 = 0x1c;
	eth_dmac.byte4 = 0x8a;
	eth_dmac.byte5 = 0x1e;
	eth_dmac.byte6 = 0xee;
	/* Ethernet source address */
	eth_smac.byte1 = 0xa0;
	eth_smac.byte2 = 0x48;
	eth_smac.byte3 = 0x1c;
	eth_smac.byte4 = 0x8c;
	eth_smac.byte5 = 0x1e;
	eth_smac.byte6 = 0x96;
}