#ifndef ORM_TYPES_H_INCLUDED
#define ORM_TYPES_H_INCLUDED

#include <pcap.h>

#define DATA_SIZE 4

#define ETH_LEN sizeof(eth_header_struct)
#define IPH_LEN sizeof(ip_header_struct)
#define UDP_LEN sizeof(udp_header_struct)
#define DAT_LEN sizeof(pkt_data_struct)
#define TOT_LEN ETH_LEN+IPH_LEN+UDP_LEN+DAT_LEN

/* 6 bytes MAC address */
typedef struct mac_address_struct
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}mac_address_struct;

/* Ethernet header */
typedef struct eth_header_struct
{
	mac_address_struct daddr;	// Destination address
	mac_address_struct saddr;	// Source address
	u_char eth_type[2];			// Ethernet type
}eth_header_struct;

/* 4 bytes IP address */
typedef struct ip_address_struct
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address_struct;

/* IPv4 header */
typedef struct ip_header_struct
{
	u_char	ver_ihl;				// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;					// Type of service 
	u_short tlen;					// Total length 
	u_short identification;			// Identification
	u_short flags_fo;				// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;					// Time to live
	u_char	proto;					// Protocol
	u_short crc;					// Header checksum
	ip_address_struct	saddr;		// Source address
	ip_address_struct	daddr;		// Destination address
}ip_header_struct;

/* UDP header*/
typedef struct udp_header_struct
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header_struct;

/* Packet header and data */
typedef struct pkt_data_struct
{
	int seq;				//Sequence number
	int ack;				//Acknowledgement
	u_char data[DATA_SIZE];	//Data
}pkt_data_struct;

#endif /* ORM_TYPES_H_INCLUDED */