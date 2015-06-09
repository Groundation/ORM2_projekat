#ifndef PROTO_H_INCLUDED
#define PROTO_H_INCLUDED

#include "global.h"

void	FindAllDevices();

pcap_t* SelectAndOpenDevice();

int		CompileAndSetFilter(pcap_t* adhandle);

void	PacketHandler(pcap_t* adhandle, u_char *pkt, u_char *ack_pkt, u_char first_pkt, int id);

void	PreparePacket();

void*	AdapterThread(void* param);

#endif