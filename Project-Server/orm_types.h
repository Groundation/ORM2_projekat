#include <pcap.h>

#define DATA_SIZE 4
#define ETH_LEN 14
#define IP_LEN 20
#define UDP_LEN 8
#define TOT_LEN ETH_LEN + IP_LEN + UDP_LEN
#define LAST_SEQ -1
#define TRUE 1
#define FALSE 0
#define SWS 5 //sliding window size

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

/* Ethernet header */
typedef struct eth_header
{
	u_char dest[6];
	u_char source[6];
	u_char eth_type[2];
}eth_header;

/* Sliding window */
typedef struct sld_window
{
	u_char left;
	u_char right;
}sld_window;