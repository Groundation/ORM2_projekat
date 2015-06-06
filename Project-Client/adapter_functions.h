#ifndef ADAPTER_FUNCTIONS_H_INCLUDED
#define ADAPTER_FUNCTIONS_H_INCLUDED

#include <pcap.h>
#include "globals.h"

void FindAllDevices();
pcap_t* SelectAndOpenDevice();
int CompileAndSetFilter(pcap_t* adhandle);

#endif /* ADAPTER_FUNCTIONS_H_INCLUDED */