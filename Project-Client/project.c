// RT-RK
// Osnovi Racunarskih Mreza 2
// File name: project.c

#include <pcap.h>
#include <pthread.h>
#include "package_functions.h"
#include "adapter_functions.h"
#include "windows.h"

void WifThread(void *param)
{
	pcap_t			*adhandle;



}

void EthThread(void *param)
{
	pcap_t			*adhandle;


}

int main()
{
	pthread_t wif_thread;
	pthread_t eth_thread;

	pcap_t			*adhandle;

	pkt_data_struct *pd_ptr;
	pkt_data_struct	*test;

	int num_of_read_bytes	= 0;
	int seq					= 0;
	int timeout				= 0;
	int mili_sec			= 0;
	int num_retrans			= 0;

	struct pcap_pkthdr	*pkt_header;
	const u_char		*pkt_data;

	char data[DATA_SIZE];
	
	SetupMacAdress();

	InitPackets(eth_buffer, eth_dmac, eth_smac);
	InitPackets(wif_buffer, wif_dmac, wif_smac);

	FindAllDevices();

	adhandle = SelectAndOpenDevice();
	CompileAndSetFilter(adhandle);

	file_ptr = fopen("test.txt","rb");
	if (!file_ptr)
	{
		printf("Unable to open file!");
		return 1;
	}
	
	while(1)
	{
		num_of_read_bytes = fread(data, 1, DATA_SIZE, file_ptr);
		if(num_of_read_bytes < DATA_SIZE)
		{
			seq = -seq;
			printf("Last ");
		}
		PreparePacket(eth_buffer, data, seq, num_of_read_bytes);
		seq++;
		if (pcap_sendpacket(adhandle, eth_buffer, TOT_LEN) != 0)
		{
			fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(adhandle));
			return;
		}
		printf("Packet sent!\n");
		test = (pkt_data_struct*) (eth_buffer + TOT_LEN - DAT_LEN);
		/* Retrieve the packets */
		/*while((timeout = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0)
		{*/
			/* Timeout occured */
			/*if(timeout == 0)
			{*/
				/*if(mili_sec == 400*num_retrans)
				{
					pcap_sendpacket(adhandle, buffer, TOT_LEN);
					printf("Retransmission...\n");
					mili_sec = 0;
					if(num_retrans == (5-1))
					{
						printf("\nShutdown!\n");
						return 1;
					} else
					{
						num_retrans++;
					}
				} else
				{
					mili_sec++;
				}*/
			/*} else
			{
				pd_ptr = (pkt_data_struct*) (pkt_data + TOT_LEN - DAT_LEN);
				if(pd_ptr -> ack == test->seq+1)
				{
					mili_sec = 0;
					num_retrans = 0;
					break;
				}
			}
		}*/
		/* Is it the end of the file? */
		if(num_of_read_bytes < DATA_SIZE)
			break;
	}

	fclose(file_ptr);

	return 0;
}