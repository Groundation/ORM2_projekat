#ifndef GLOBALS_H_INCLUDED
#define GLOBALS_H_INCLUDED

#include "pthread.h"
#include "semaphore.h"
#include "types.h"
#include <pcap.h>

/* semaphore for signalizing when packet arrives */
sem_t pkt_arrived;

pthread_mutex_t mtx;
pthread_mutex_t file;
pthread_mutex_t terminal;

/* Variables for Adapter thread */
int num_pkts;
int total_num_pkts;

/* true when thread needs to finish */
u_char end_thr[2];

/* remembers last received sequence number in case of retransmission of packets */
int previous_seq;

/* true when last packet arrives so program can finish regulary */
u_char last_pkt;

/* variables for device list */
pcap_if_t *alldevs;
pcap_if_t *d;

/* file pointer */
FILE* fd;
	
/* temp numeric variables */
int num_inter; 

#endif