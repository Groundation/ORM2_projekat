// RT-RK
// Osnovi Racunarskih Mreza 2
// File name: project.c

#include <pcap.h>
#include <pthread.h>
#include "package_functions.h"
#include "adapter_functions.h"
#include "windows.h"

#define WIF_THREAD 0
#define ETH_THREAD 1

void *Thread(void *param)
{
	pcap_t			*adhandle;

	pkt_data_struct *pd_ptr;

	struct pcap_pkthdr *header;

	int ex_ack				= 0;
	int timeout				= 0;
	int mili_sec			= 0;
	int num_retrans			= 0;
	
	u_char *buffer			= NULL;

	u_char data[DATA_SIZE];
	u_char *pkt_data;

	u_char disconnect		= 0;

	char device[51];
	u_int netmask;

	u_char id = (u_char) param;

	pthread_mutex_lock(&term_mutx);
	if(id == ETH_THREAD)
	{
		printf("Ethernet ");
		buffer = eth_buffer;
	} else //id == WIF_THREAD
	{
		printf("Wifi ");
		buffer = wif_buffer;
	}
	adhandle = SelectAndOpenDevice(1, device, &netmask);
	CompileAndSetFilter(adhandle, 1, netmask);
	pthread_mutex_unlock(&term_mutx);

	if(id == ETH_THREAD)
	{
		sem_post(&wif_init);
		sem_wait(&eth_init);

	} else //id == WIF_THREAD
	{
		sem_post(&eth_init);
		sem_wait(&wif_init);
	}
	

	while(1)
	{	
		/*while(disconnect)
		{
			Sleep(1000);
			if((adhandle = OpenDevice(device)) != NULL)
			{
				CompileAndSetFilter(adhandle, 1, netmask);
				disconnect = 0;
			}
		}*/
		if(FillPacket(buffer, &ex_ack) == 1)
			break;
		if (pcap_sendpacket(adhandle, buffer, TOT_LEN) != 0)
		{
			//fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(adhandle));
			disconnect = 1;
			printf("Prekinuta konekcija!");
			while(disconnect)
			{
				Sleep(1000);
				if((adhandle = OpenDevice(device)) != NULL)
				{
					CompileAndSetFilter(adhandle, 1, netmask);
					disconnect = 0;
				}
			}
		}
		/* Retrieve the packets */
		while(1)
		{
			timeout = pcap_next_ex(adhandle, &header, &pkt_data);
			if(timeout < 0)
			{
				disconnect = 1;
				printf("Prekinuta konekcija!");
				while(disconnect)
				{
					Sleep(1000);
					if((adhandle = OpenDevice(device)) != NULL)
					{
						CompileAndSetFilter(adhandle, 1, netmask);
						disconnect = 0;
					}
				}
			}
			if(timeout == 0)
			{
				if(mili_sec == 10*(num_retrans+1))
				{
					pcap_sendpacket(adhandle, buffer, TOT_LEN);
					printf("Retransmission...\n");
					mili_sec = 0;
					if(num_retrans == 3)
					{
						num_retrans = 3;
					} else
					{
						num_retrans++;
					}
				} else
				{
					mili_sec++;
				}
			}
			if(timeout > 0)
			{
				pd_ptr = (pkt_data_struct*) (pkt_data + TOT_LEN - DAT_LEN);
				//printf("Dobio je ack: %d, a treba: %d.", pd_ptr -> ack, ex_ack);
				if(pd_ptr -> ack == ex_ack)
				{
					mili_sec = 0;
					num_retrans = 0;
					break;
				}
			}
		}
	}
}

int main()
{
	pthread_t wif_thread;
	pthread_t eth_thread;
	
	SetupMacAdress();

	InitPackets(eth_buffer, eth_dmac, eth_smac);
	InitPackets(wif_buffer, wif_dmac, wif_smac);

	FindAllDevices();

	pthread_mutex_init(&term_mutx, NULL);
	pthread_mutex_init(&file_mutx, NULL);

	sem_init(&eth_init, 0, 0);
	sem_init(&wif_init, 0, 0);

	file_ptr = fopen("slika3.jpg","rb");
	if (!file_ptr)
	{
		printf("Unable to open file!");
		return 1;
	}
	
	pthread_create(&wif_thread, NULL, Thread, (void*) 0);
	pthread_create(&eth_thread, NULL, Thread, (void*) 1);

	pthread_join(eth_thread, NULL);
	pthread_join(wif_thread, NULL);

	pthread_mutex_destroy(&term_mutx);
	pthread_mutex_destroy(&file_mutx);

	sem_destroy(&eth_init);
	sem_destroy(&wif_init);

	pcap_freealldevs(alldevs);
	fclose(file_ptr);

	return 0;
}