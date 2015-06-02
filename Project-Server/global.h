/* semaphore for signalizing when packet arrives */
static sem_t pkt_arrived;

/* pthread for creating buffering thrread */
static pthread_t buf_thr;

static pthread_mutex_t mtx;
static sem_t pkt_start;

/* Variables for writing thread */
char buf_rcv[10][DATA_SIZE];
u_char n_block;
u_char seq;
u_char more_pkts;
u_char useful_bytes;
u_char wr_end;

/* variables for device list */
pcap_if_t *alldevs;
pcap_if_t *d;

/* remembers last received sequence number in case of retransmission of packets */
int previous_seq;

/* signalising main when last packet arrives so program can finish regulary */
u_char last_pkt;

/* pointer to data part of received packet */
pkt_data *pd;
pkt_data *ack_pd;

u_char* ack_pkt;