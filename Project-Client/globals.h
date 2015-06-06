#ifndef GLOBALS_H_INCLUDED
#define GLOBALS_H_INCLUDED

#include "orm_types.h"
#include "pthread.h"
#include "semaphore.h"

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

u_char wif_buffer[TOT_LEN];
u_char eth_buffer[TOT_LEN];

pthread_mutex_t term_mutx;
pthread_mutex_t file_mutx;

sem_t			eth_init;
sem_t			wif_init;

#endif /* ORM_TYPES_H_INCLUDED */