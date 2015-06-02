// RT-RK
// Osnovi Racunarskih Mreza 2
// File name: project.c

#include <pcap.h>
#include <pthread.h>
#include "package_functions.h"
#include "windows.h"
 
int main()
{
	pkt_data_struct *pd_ptr;
	pcap_if_t		*alldevs; 
	pcap_if_t		*d;
	pkt_data_struct	*pd;
	pkt_data_struct	*test;
	int n;
	int num_of_read_bytes = 0;
	int seq = 0;
	int res;
	int inum;
	int i=0;
	int j=0;
	int k=0;
	int br_trans = 1;
	int lenght;
	pcap_t *adhandle;
	struct pcap_pkthdr* pkt_header;
	const u_char *pkt_data;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ip and udp and dst port 50020";
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
	inum = 1;
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
							 1,				// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
	if(pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
		
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	if(d->addresses != NULL)
		
		netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		
		netmask=0xffffff; 


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
	{
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
		
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	//set the filter
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr,"\nError setting the filter.\n");
		
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	pcap_freealldevs(alldevs);

	ptr_myfile = fopen("slika.jpg","rb");
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
			seq = -seq;
		}
		PreparePacket(buf, read_data, seq, num_of_read_bytes);
		seq++;
		if (pcap_sendpacket(adhandle, buf, TOT_LEN) != 0)
		{
			fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(adhandle));
			return;
		}

		test = (pkt_data_struct*) (buf + TOT_LEN - DAT_LEN);
		/* Retrieve the packets */
		while((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0)
		{

			if(res == 0)
			{
				if(j == 400*br_trans)
				{
					pcap_sendpacket(adhandle, buf, TOT_LEN);
					printf("uradio sam transmisiju");
					j = 0;
					if(br_trans == 5)
					{
						printf("\nnije uspeo da posalje paket posle dosta transmisija\n");
						return 1;
					} else
					{
						br_trans++;
					}
				} else
				{
					j++;
				}
				continue;
			}

			pd_ptr = (pkt_data_struct*) (pkt_data + TOT_LEN - DAT_LEN);
			//printf("ACK ocekivani: %d\n", test -> seq+1);
			//printf("ACK primljen: %d\n", pd_ptr -> ack);
			if(pd_ptr -> ack == test->seq+1)
			{
				j = 0;
				br_trans = 1;
				break;
			}
		}
		if(num_of_read_bytes < DATA_SIZE)
			break;
	}

	fclose(ptr_myfile);

	return 0;
}