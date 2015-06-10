#ifndef PROTO_H_INCLUDED
#define PROTO_H_INCLUDED

#include "global.h"

void	FindAndPrintAllDevices();

pcap_t* SelectAndOpenDevice(u_char id);

int		CompileAndSetFilter(pcap_t* adhandle, u_char id);

void	PacketHandler(pcap_t* adhandle, u_char *pkt, u_char *ack_pkt, u_char first_pkt, u_char connection_error, u_char id);

void	PreparePacket();

void*	AdapterThread(void* param);

#endif