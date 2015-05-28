#include "proto.h"
#include <windows.h>

void* Buffering(void* param)
{
	while(1)
	{
		
	}
}

void* Writing(void* param)
{
	while(1)
	{	
		sem_wait(&pkt_arrived);
		printf("dobio paket\n");
		printf("seq: %d\n", pd->seq);
		//printf("ack: %d\n", pd->ack);
	}
}

/* function called for every incoming packet */
void PacketHandler(const u_char *pkt, FILE* file_p)
{
	/* retrieve the position of the packet data */
	pd = (pkt_data *) (pkt + TOT_LEN);

	/*printf("dobio paket\n");
	printf("seq: %d\n", pd->seq);
	printf("ack: %d\n", pd->ack);

	if((pd->seq) >= 0)
	{
		
		fwrite(pd->data, 1, DATA_SIZE, fd);
	}
	else if((pd->seq) == LAST_SEQ) //last packet arrived
	{
		fwrite(pd->data, 1, pd->ack, fd); //pd->ack is number of useful bytes
		last_pkt = TRUE;
	}*/
	sem_post(&pkt_arrived);
}