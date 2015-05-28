/* semaphore for signalizing when packet arrives */
static sem_t pkt_arrived;
/* pthread for creating buffering thrread */
static pthread_t buf_thr;

static pthread_t inp_thr;

u_char last_pkt;
pkt_data *pd;
FILE* fd;
