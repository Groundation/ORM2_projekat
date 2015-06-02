#include <pcap.h>

#define DATA_SIZE 1464

#define ETH_LEN sizeof(eth_header)
#define IP_LEN	sizeof(ip_header)
#define UDP_LEN sizeof(udp_header)
#define DAT_LEN sizeof(pkt_data)
#define TOT_LEN ETH_LEN + IP_LEN + UDP_LEN + DAT_LEN

#define FIRST_SEQ 0
#define LAST_SEQ -1

#define TRUE 1
#define FALSE 0

#define MAC_ADDR_BYTES_NUM 6
#define SWS 4 //sliding window size

#define TMOUT 1500
#define ERROR -1

/* Packet header and data */
typedef struct pkt_data
{
	int seq;
	int ack;
	char data[DATA_SIZE];
}pkt_data;

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

/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

/* 6 bytes MAC address */
typedef struct mac_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}mac_address;

/* Ethernet header */
typedef struct eth_header
{
	mac_address daddr;	// Destination address
	mac_address saddr;	// Source address
	u_char eth_type[2];	// Ethernet type
}eth_header;

/* Sliding window */
typedef struct sld_window
{
	u_char left;
	u_char right;
}sld_window;