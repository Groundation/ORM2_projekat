#ifndef THREAD_FUNCTIONS_C_INCLUDED
#define THREAD_FUNCTIONS_C_INCLUDED

#include "thread_functions.h"

void *Reader(void *param)
{
	u_char main_thread	= WIF_THREAD;
	u_char side_thread	= ETH_THREAD;

	int i;

	for(i = 0; i < NUM_OF_THREADS; i++)
	{
		write_ready[i]	= 1;
		thread_error[i]	= 0;
	}

	while(1)
	{
		/* Switch threads */
		if(main_thread == WIF_THREAD)
		{
			main_thread	= ETH_THREAD;
			side_thread	= WIF_THREAD;
		}
		else
		{
			main_thread	= WIF_THREAD;
			side_thread	= ETH_THREAD;
		}

		/* Check if main thread is ready for new packet and if not is in ERROR */
		pthread_mutex_lock(&read_mutx[main_thread]);
		if(write_ready[main_thread] && !thread_error[main_thread])
		{
			/* Check if side thread is in ERROR */
			pthread_mutex_lock(&read_mutx[side_thread]);
			if(thread_error[side_thread])
			{
				thread_error[side_thread] = 0;
				write_ready[main_thread] = 0;
				/* Fill buffer of main thread with data from side packet */
				TransferData(side_thread, main_thread);
				pthread_mutex_unlock(&read_mutx[side_thread]);
			}
			/* Fill buffer of main thread with new packet*/
			else
			{
				pthread_mutex_unlock(&read_mutx[side_thread]);

				write_ready[main_thread] = 0;
				if(FillPacket(main_thread))
				{
					pthread_mutex_unlock(&read_mutx[main_thread]);
					break;
				}
			}
		}
		pthread_mutex_unlock(&read_mutx[main_thread]);
	}
}

void *Thread(void *param)
{
	pcap_t			*adhandle;

	pkt_data_struct *pd_ptr;

	struct pcap_pkthdr *header;

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
	}
	else //id == WIF_THREAD
	{
		printf("Wifi ");
	}

	buffer = main_buffer[id];

	adhandle = SelectAndOpenDevice(1, device, &netmask);
	CompileAndSetFilter(adhandle, 1, netmask);
	pthread_mutex_unlock(&term_mutx);

	if(id == ETH_THREAD)
	{
		sem_post(&wif_init);
		sem_wait(&eth_init);

	}
	else //id == WIF_THREAD
	{
		sem_post(&eth_init);
		sem_wait(&wif_init);
	}
	
	while(1)
	{	
		pthread_mutex_lock(&read_mutx[id]);
		if(!write_ready[id])
		{
			pthread_mutex_unlock(&read_mutx[id]);
			if (pcap_sendpacket(adhandle, buffer, TOT_LEN) != 0)	//hosts adapter is out
			{
				//fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(adhandle));
				disconnect = 1;

				pthread_mutex_lock(&read_mutx[id]);
				thread_error[id] = 1;
				pthread_mutex_unlock(&read_mutx[id]);

				printf("Disconnect occured in sending of packet!");
				while(disconnect)
				{
					Sleep(1000);
					if(last_pkt)
						break;
					if((adhandle = OpenDevice(device)) != NULL)
					{
						CompileAndSetFilter(adhandle, 1, netmask);
						thread_error[id] = 0;
						disconnect = 0;
					}
				}
			}

			/* Retrieve the packets */
			while(1)
			{
				timeout = pcap_next_ex(adhandle, &header, &pkt_data);
				if(timeout < 0)	//Hosts adapter is out
				{
					disconnect = 1;

					pthread_mutex_lock(&read_mutx[id]);
					thread_error[id] = 1;
					pthread_mutex_unlock(&read_mutx[id]);

					printf("Disconnect occured in fetching of packet!");
					while(disconnect)
					{
						Sleep(1000);
						if(last_pkt)
							break;
						if((adhandle = OpenDevice(device)) != NULL)
						{
							CompileAndSetFilter(adhandle, 1, netmask);
							thread_error[id] = 0;
							disconnect = 0;
						}
					}
				}
				else if(timeout == 0) //Servers adapter is out
				{
					if(mili_sec == 50*(num_retrans+1))
					{
						pcap_sendpacket(adhandle, buffer, TOT_LEN);
						printf("Retransmission...\n");
						mili_sec = 0;
						if(num_retrans < 3)
						{
							num_retrans++;
						}
						else if(num_retrans == 3)
						{
							pthread_mutex_lock(&read_mutx[id]);
							thread_error[id] = 1;
							printf("Error in retransmission...\n");
							pthread_mutex_unlock(&read_mutx[id]);
							num_retrans++;
						} else
						{
							if(last_pkt)
								break;
						}
					} 
					else
					{
						mili_sec++;
					}
				}
				else	//Packet received
				{
					pd_ptr = (pkt_data_struct*) (pkt_data + TOT_LEN - DAT_LEN);
					if(pd_ptr -> ack == ack_to_receive[id])
					{
						mili_sec = 0;
						num_retrans = 0;
						write_ready[id] = 1;
						thread_error[id] = 0;
						break;
					}
				}
				if(last_pkt)
					break;
			}
		}
		else
		{
			pthread_mutex_unlock(&read_mutx[id]);
		}

		if(last_pkt)
			break;
	}
}

#endif /* THREAD_FUNCTIONS_C_INCLUDED */