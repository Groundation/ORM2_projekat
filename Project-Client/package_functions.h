#ifndef PACKAGE_FUNCTIONS_H_INCLUDED
#define PACKAGE_FUNCTIONS_H_INCLUDED

#include <pcap.h>
#include "orm_types.h"
#include "globals.h"

void InitPackets(u_char *, mac_address_struct, mac_address_struct);
void PrepareData(u_char *, char *, int, int);
void SetupMacAdress();

#endif /* PACKAGE_FUNCTIONS_H_INCLUDED */