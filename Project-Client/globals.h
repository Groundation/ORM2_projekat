#ifndef GLOBALS_H_INCLUDED
#define GLOBALS_H_INCLUDED

#define WIF_THREAD 0
#define ETH_THREAD 1

#include "orm_types.h"
#include "pthread.h"
#include "semaphore.h"

#define NUM_OF_THREADS 2

FILE			*file_ptr;

pcap_if_t		*alldevs;
pcap_if_t		*d;

int				seq;	
int				num_inter;

u_char			last_pkt;

mac_address_struct	eth_smac;
mac_address_struct	eth_dmac;
mac_address_struct	wif_smac;
mac_address_struct	wif_dmac;

u_char main_buffer[NUM_OF_THREADS][TOT_LEN];
u_char write_ready[NUM_OF_THREADS];
int ack_to_receive[NUM_OF_THREADS];
u_char thread_error[NUM_OF_THREADS];

pthread_mutex_t term_mutx;
pthread_mutex_t read_mutx[NUM_OF_THREADS];

sem_t			eth_init;
sem_t			wif_init;

#endif /* ORM_TYPES_H_INCLUDED */