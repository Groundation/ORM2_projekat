#ifndef ADAPTER_FUNCTIONS_C_INCLUDED
#define ADAPTER_FUNCTIONS_C_INCLUDED

#include "adapter_functions.h"

void FindAllDevices()
{
	/* Buffer needed in case of error while searching devices */
	char			errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++num_inter, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
}

pcap_t* OpenDevice(char *device)
{
	/* Buffer needed in case of error while searching devices */
	char			errbuf[PCAP_ERRBUF_SIZE];

	/* Return value */
	pcap_t			*ret_adhandle	= NULL;

	/* Open the adapter */
	if ((ret_adhandle = pcap_open_live(device,	// name of the device
							 65536,				// portion of the packet to capture. 
												// 65536 grants that the whole packet will be captured on all the MACs.
							 1,					// promiscuous mode (nonzero means promiscuous)
							 1,					// read timeout
							 errbuf				// error buffer
							 )) == NULL)
	{
		return NULL;
	} else
	{
		printf("\nUSPEO SAM.\n");
	}

	return ret_adhandle;
}

pcap_t* SelectAndOpenDevice(u_char opt, char *device, u_int *netmask)
{
	/* Buffer needed in case of error while searching devices */
	char			errbuf[PCAP_ERRBUF_SIZE];
	
	/* Temp numeric variables */
	int				i		= 0;
	int				inum	= 0;

	/* Return value */
	pcap_t			*ret_adhandle	= NULL;
	
	printf("Enter the interface number (1-%d):", num_inter);
	scanf("%d", &inum);

	/* Check if the user specified a valid adapter */
	if(inum < 1 || inum >num_inter)
	{
		printf("\nAdapter number out of range.\n");
		return NULL;
	}

	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

	/* Open the adapter */
	if ((ret_adhandle = pcap_open_live(d->name,	// name of the device
							 65536,				// portion of the packet to capture. 
												// 65536 grants that the whole packet will be captured on all the MACs.
							 1,					// promiscuous mode (nonzero means promiscuous)
							 1,					// read timeout
							 errbuf				// error buffer
							 )) == NULL)
	{
		printf("\nUnable to open the adapter.\n");
		return NULL;
	}

	if(opt)
	{
		strcpy(device, d->name);
		if(d->addresses != NULL)
			/* Retrieve the mask of the first address of the interface */
			*netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
		else
			/* If the interface is without addresses we suppose to be in a C class network */
			*netmask = 0xffffff; 
	}

	return ret_adhandle;
}

int CompileAndSetFilter(pcap_t *adhandle, u_char opt, u_int netmask_in)
{
	char packet_filter[] = "ip and udp and dst port 60030";
	struct bpf_program fcode;
	struct pcap_pkthdr *header;
	u_int netmask;
	
	/* Check the link layer. We support only Ethernet for simplicity. */
	if(pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return ERROR;
	}
	
	if(opt)
	{
		netmask = netmask_in;
	} else
	{
		if(d->addresses != NULL)
			/* Retrieve the mask of the first address of the interface */
			netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
		else
			/* If the interface is without addresses we suppose to be in a C class network */
			netmask = 0xffffff;
	}

	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return ERROR;
	}
	
	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return ERROR;
	}
	
	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr,"\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return ERROR;
	}

	return 1;
}

#endif /* ADAPTER_FUNCTIONS_C_INCLUDED */