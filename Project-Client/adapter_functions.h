#ifndef ADAPTER_FUNCTIONS_H_INCLUDED
#define ADAPTER_FUNCTIONS_H_INCLUDED

#include <pcap.h>
#include "globals.h"

void FindAllDevices();
pcap_t* OpenDevice(char *);
pcap_t* SelectAndOpenDevice(u_char, char *, u_int *);
int CompileAndSetFilter(pcap_t *, u_char, u_int);

#endif /* ADAPTER_FUNCTIONS_H_INCLUDED */