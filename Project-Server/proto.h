#include "global.h"

/* prototype of the packet handler */
void PacketHandler(pcap_t* adhandle, u_char *pkt, FILE* file_p);

/* prototype of the buffering thread */
void* Buffering(void* param);

/* prototype of writing file thread */
void* Writing(void* param);