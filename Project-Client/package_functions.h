#ifndef PACKAGE_FUNCTIONS_H_INCLUDED
#define PACKAGE_FUNCTIONS_H_INCLUDED

#include <pcap.h>
#include "orm_types.h"

void PreparePacket(u_char *packet, char *data, int seq, int bytes);

#endif /* PACKAGE_FUNCTIONS_H_INCLUDED */