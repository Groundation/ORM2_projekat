/* semaphore for signalizing when packet arrives */
static sem_t pkt_arrived;
/* pthread for creating buffering thrread */
static pthread_t buf_thr;

static pthread_mutex_t mtx;
static sem_t pkt_start;

/* Variables when using writing thread */
char buf_rcv[10][DATA_SIZE];
u_char n_block;
u_char seq;
u_char more_pkts;
u_char useful_bytes;
u_char wr_end;


u_char last_pkt;
pkt_data *pd;
FILE* fd;
