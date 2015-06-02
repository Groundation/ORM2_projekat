#include "global.h"

pcap_t* SelectAndOpenDevice();

int CompileAndSetFilter(pcap_t* adhandle);

void PacketHandler(pcap_t* adhandle, u_char *pkt, FILE* file_p);

void PreparePacket();

/* prototype of buffering thread */
void* Buffering(void* param);

/* prototype of writing file thread */
void* Writing(void* param);