// RT-RK
// Osnovi Racunarskih Mreza 2
// File name: project.c

#include "types.h"
#include "pthread.h"
#include "semaphore.h"
#include "global.h"
#include "proto.h"
#include "fun.c"

int main()
{	
	/*******************************/
	/**** VARIABLES DECLARATION ****/
	/*******************************/

	/* handler of opened device */
	pcap_t *adhandle;
	
	/* packet buffer */
	u_char *pkt;
	
	/* temp variables needed for pcap_next_ex */
	int res;
	struct pcap_pkthdr *header;

	/* counter for timeout */
	int n = 0;

	/* file pointer */
	FILE* fd;



	/**********************/
	/**** MAIN PROGRAM ****/
	/**********************/

	/* init global variables */
	previous_seq = FIRST_SEQ - 1;
	last_pkt = FALSE;

	/* NEEDED FOR WRITING THREAD */
	/*wr_end = FALSE;
	n_block = 0;
	seq = 0;
	more_pkts = 0;
	useful_bytes = 0;
	*/
	/* init semaphore */
	//sem_init(&pkt_arrived, 0, 0);
	/* create thread Buffering*/
	//pthread_create(&buf_thr, NULL, Writing, NULL);
	//pthread_mutex_init(&mtx, NULL);
	/* TODO: init sliding window */
	


	/* Retrieve device list, select apropriate device and open that device */
	if((adhandle = SelectAndOpenDevice()) == NULL)
		return ERROR;
	
	/* Check link layer, retrieve netmask, compile and set filter */
	if(CompileAndSetFilter(adhandle) == ERROR)
		return ERROR;

	/* Open file for writing */
	fd = fopen("slika1.jpg", "wb");

	/* Retrieve the packets */
    while((res = pcap_next_ex(adhandle, &header, &pkt)) >= 0){
        
		if(res == 0) //read timeout
		{
			//printf("%d\n", n);
			//if(++n == TMOUT)
				//break;
			
			continue;
		}
		
		n = 0; //reset timeout counter

		/* Send ACK and write user data to file*/
		PacketHandler(adhandle, pkt, fd);
		
		if(last_pkt)
			break;
		
    }

	//pthread_join(buf_thr, NULL);
	printf("izasao\n");
	
	/* Close file */
	fclose(fd);

	printf("zatvorio\n");
	/*destroy semaphore */
	//sem_destroy(&pkt_arrived);
	//pthread_mutex_destroy(&mtx);

	return 0;
}
