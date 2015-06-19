#ifndef THREAD_FUNCTION_H_DEFINE
#define THREAD_FUNCTION_H_DEFINE

#include <pcap.h>
#include <pthread.h>
#include "package_functions.h"
#include "adapter_functions.h"
#include "windows.h"

void *Reader(void *param);
void *Thread(void *param);

#endif /* THREAD_FUNCTIONS_H_INCLUDED */