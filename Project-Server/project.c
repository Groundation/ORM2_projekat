#ifndef PROJECT_C_INCLUDED
#define PROJECT_C_INCLUDED

// RT-RK
// Osnovi Racunarskih Mreza 2
// File name: project.c

#include "fun.h"

int main()
{	
	/*******************************/
	/**** VARIABLES DECLARATION ****/
	/*******************************/

	/* counter for timeout */
	int n = 0;

	/* id's for threads */
	pthread_t wifi_thr;
	pthread_t eth_thr;

	/*******************************/
	/**** GLOBAL VARIABLES INIT ****/
	/*******************************/
	
	last_pkt = FALSE;
	num_pkts = 0;
	total_num_pkts = 0;
	end_thr[0] = FALSE;
	end_thr[1] = FALSE;
	num_inter = 0;

	/**********************/
	/**** MAIN PROGRAM ****/
	/**********************/

	fd = fopen("banana.jpg", "wb");

	pthread_mutex_init(&mtx, NULL);
	pthread_mutex_init(&file, NULL);
	pthread_mutex_init(&terminal, NULL);

	FindAndPrintAllDevices();

	pthread_create(&wifi_thr, NULL, AdapterThread, (void*) WIFI_ID);
	pthread_create(&eth_thr, NULL, AdapterThread, (void*) ETH_ID);

	pthread_join(wifi_thr, NULL);
	pthread_join(eth_thr, NULL);
	
	pthread_mutex_destroy(&mtx);
	pthread_mutex_destroy(&file);
	pthread_mutex_destroy(&terminal);

	fclose(fd);
	pcap_freealldevs(alldevs);

	return 0;
}

#endif
