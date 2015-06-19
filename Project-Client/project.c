// RT-RK
// Osnovi Racunarskih Mreza 2
// File name: project.c

#include "thread_functions.h"

int main()
{
	pthread_t read_thread;
	pthread_t wif_thread;
	pthread_t eth_thread;
	
	SetupMacAdress();

	InitPackets(main_buffer[ETH_THREAD], eth_dmac, eth_smac);
	InitPackets(main_buffer[WIF_THREAD], wif_dmac, wif_smac);

	FindAllDevices();

	pthread_mutex_init(&term_mutx, NULL);
	pthread_mutex_init(&read_mutx[WIF_THREAD], NULL);
	pthread_mutex_init(&read_mutx[ETH_THREAD], NULL);

	sem_init(&eth_init, 0, 0);
	sem_init(&wif_init, 0, 0);

	file_ptr = fopen("file_1MB.txt","rb");
	if (!file_ptr)
	{
		printf("Unable to open file!");
		return 1;
	}
	
	pthread_create(&read_thread, NULL, Reader, NULL);
	pthread_create(&wif_thread, NULL, Thread, (void*) WIF_THREAD);
	pthread_create(&eth_thread, NULL, Thread, (void*) ETH_THREAD);

	pthread_join(read_thread, NULL);
	pthread_join(wif_thread, NULL);
	pthread_join(eth_thread, NULL);

	pthread_mutex_destroy(&term_mutx);
	pthread_mutex_destroy(&read_mutx[WIF_THREAD]);
	pthread_mutex_destroy(&read_mutx[ETH_THREAD]);

	sem_destroy(&eth_init);
	sem_destroy(&wif_init);

	pcap_freealldevs(alldevs);
	fclose(file_ptr);

	return 0;
}