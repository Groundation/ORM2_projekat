// RT-RK
// Osnovi Racunarskih Mreza 2
// File name: project.c

#include <pcap.h>
#include <pthread.h>
#include "package_functions.h"
 
int main()
{
	pcap_if_t		*alldevs; 
	pcap_if_t		*d;
	pkt_data_struct	*pd;
	int n;
	int num_of_read_bytes = 0;
	int seq = 0;

	int inum;
	int i=0;
	int lenght;
	pcap_t *adhandle;
	struct pcap_pkthdr* pkt_header;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ip and udp and dst port 50030";
	struct bpf_program fcode;

	FILE *ptr_myfile;
	u_char buf[TOT_LEN];
	char read_data[DATA_SIZE];
	
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	
	//printf("Enter the interface number (1-%d):",i);
	//scanf("%d", &inum);
	inum=2;
	/* Check if the user specified a valid adapter */
	if(inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");
		
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the adapter */
	if ((adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	ptr_myfile = fopen("test.txt","rb");
	if (!ptr_myfile)
	{
		printf("Unable to open file!");
		return 1;
	}

	while(1)
	{
		num_of_read_bytes = fread(read_data, 1, DATA_SIZE, ptr_myfile);
		if(num_of_read_bytes < DATA_SIZE)
		{
			PreparePacket(buf, read_data, -1, num_of_read_bytes);
			if (pcap_sendpacket(adhandle, buf, TOT_LEN) != 0)
			{
				fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(adhandle));
				return;
			}
			break;
		} else
		{ 
			PreparePacket(buf, read_data, seq, 0);
			seq++;
			if (pcap_sendpacket(adhandle, buf, TOT_LEN) != 0)
			{
				fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(adhandle));
				return;
			}
		}
	}

	fclose(ptr_myfile);

	return 0;
}