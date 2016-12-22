/*
 * Author Jerry Lundström <jerry@dns-oarc.net>
 * Copyright (c) 2016, OARC, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __pcap_thread_h
#define __pcap_thread_h

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

#include <pcap/pcap.h>
#include <sys/time.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PCAP_THREAD_VERSION_STR     "1.2.0"
#define PCAP_THREAD_VERSION_MAJOR   1
#define PCAP_THREAD_VERSION_MINOR   2
#define PCAP_THREAD_VERSION_PATCH   0

#define PCAP_THREAD_DEFAULT_TIMEOUT     1000
#define PCAP_THREAD_DEFAULT_QUEUE_SIZE  64
#define PCAP_THREAD_DEFAULT_QUEUE_WAIT  { 0, 10000 }
#ifdef HAVE_PTHREAD
#define PCAP_THREAD_DEFAULT_QUEUE_MODE PCAP_THREAD_QUEUE_MODE_COND
#else
#ifdef HAVE_SCHED_YIELD
#define PCAP_THREAD_DEFAULT_QUEUE_MODE PCAP_THREAD_QUEUE_MODE_YIELD
#else
#define PCAP_THREAD_DEFAULT_QUEUE_MODE PCAP_THREAD_QUEUE_MODE_WAIT
#endif
#endif
#define PCAP_THREAD_DEFAULT_CALLBACK_QUEUE_MODE PCAP_THREAD_QUEUE_MODE_DROP
#define PCAP_THREAD_DEFAULT_CALLBACK_QUEUE_WAIT { 0, 10000 }

#define PCAP_THREAD_OK              0
#define PCAP_THREAD_EPCAP           1
#define PCAP_THREAD_ENOMEM          2
#define PCAP_THREAD_ENOMON          3
#define PCAP_THREAD_ENODIR          4
#define PCAP_THREAD_EINVAL          5
#define PCAP_THREAD_EWOULDBLOCK     6
#define PCAP_THREAD_NOPCAPS         7
#define PCAP_THREAD_NOCALLBACK      8
#define PCAP_THREAD_ERRNO           9
#define PCAP_THREAD_NOYIELD         10

#define PCAP_THREAD_EPCAP_STR       "libpcap error"
#define PCAP_THREAD_ENOMEM_STR      "out of memory"
#define PCAP_THREAD_ENOMON_STR      "monitor mode requested but not supported"
#define PCAP_THREAD_ENODIR_STR      "direction specified but not supported"
#define PCAP_THREAD_EINVAL_STR      "invalid argument"
#define PCAP_THREAD_EWOULDBLOCK_STR "nonblocking pcap can not be added"
#define PCAP_THREAD_NOPCAPS_STR     "nothing to capture on"
#define PCAP_THREAD_NOCALLBACK_STR  "no callback set"
#define PCAP_THREAD_ERRNO_STR       "system error, check errno"
#define PCAP_THREAD_NOYIELD_STR     "queue more yield requested but not supported"

typedef enum pcap_thread_queue_mode pcap_thread_queue_mode_t;
typedef struct pcap_thread pcap_thread_t;
typedef void (*pcap_thread_callback_t)(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* pkt, const char* name, int dlt);
typedef void (*pcap_thread_stats_callback_t)(u_char* user, const struct pcap_stat* stats, const char* name, int dlt);
#ifndef HAVE_PCAP_DIRECTION_T
typedef int pcap_direction_t;
#endif
typedef struct pcap_thread_pcaplist pcap_thread_pcaplist_t;

enum pcap_thread_queue_mode {
    PCAP_THREAD_QUEUE_MODE_COND,
    PCAP_THREAD_QUEUE_MODE_WAIT,
    PCAP_THREAD_QUEUE_MODE_YIELD,
    PCAP_THREAD_QUEUE_MODE_DROP
};

#ifdef HAVE_PCAP_DIRECTION_T
#define PCAP_THREAD_T_INIT_DIRECTION_T 0,
#else
#define PCAP_THREAD_T_INIT_DIRECTION_T
#endif

#ifdef HAVE_PTHREAD
#define PCAP_THREAD_T_INIT_QUEUE PTHREAD_COND_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, 0,
#else
#define PCAP_THREAD_T_INIT_QUEUE
#endif

#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
#define PCAP_THREAD_T_INIT_PRECISION PCAP_TSTAMP_PRECISION_MICRO
#else
#define PCAP_THREAD_T_INIT_PRECISION 0
#endif

#define PCAP_THREAD_T_INIT { \
    1, PCAP_THREAD_DEFAULT_QUEUE_MODE, PCAP_THREAD_DEFAULT_QUEUE_WAIT, PCAP_THREAD_DEFAULT_CALLBACK_QUEUE_MODE, PCAP_THREAD_DEFAULT_CALLBACK_QUEUE_WAIT, PCAP_THREAD_T_INIT_QUEUE \
    0, 0, 0, 0, PCAP_THREAD_DEFAULT_TIMEOUT, \
    0, 0, PCAP_THREAD_T_INIT_PRECISION, 0, PCAP_THREAD_T_INIT_DIRECTION_T \
    0, 0, { 0, 0 }, 1, PCAP_NETMASK_UNKNOWN, \
    PCAP_THREAD_DEFAULT_QUEUE_SIZE, 0, 0, \
    0, "", 0, 0, { 0, 0 } \
}

struct pcap_thread {
    int                         use_threads;
    pcap_thread_queue_mode_t    queue_mode;
    struct timeval              queue_wait;
    pcap_thread_queue_mode_t    callback_queue_mode;
    struct timeval              callback_queue_wait;
#ifdef HAVE_PTHREAD
    pthread_cond_t              queue_cond;
    pthread_mutex_t             queue_mutex;
    int                         queue_run;
#endif

    int                     snapshot;
    int                     snaplen;
    int                     promiscuous;
    int                     monitor;
    int                     timeout;

    int                     buffer_size;
    int                     timestamp_type;
    int                     timestamp_precision;
    int                     immediate_mode;
#ifdef HAVE_PCAP_DIRECTION_T
    pcap_direction_t        direction;
#endif

    char*                   filter;
    size_t                  filter_len;
    struct bpf_program      bpf;
    int                     filter_optimize;
    bpf_u_int32             filter_netmask;

    size_t                  queue_size;
    pcap_thread_callback_t  callback;
    pcap_thread_callback_t  dropback;

    int                     status;
	char                    errbuf[PCAP_ERRBUF_SIZE];
    pcap_thread_pcaplist_t* pcaplist;
    pcap_thread_pcaplist_t* step;

    struct timeval          timedrun;
};

#define PCAP_THREAD_SET_ERRBUF(x, y) strncpy(x->errbuf, y, sizeof(x->errbuf) - 1)

#ifdef HAVE_PTHREAD
#define PCAP_THREAD_PCAPLIST_T_INIT { \
    0, 0, 0, 0, 0, 0, \
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, PTHREAD_COND_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, PCAP_THREAD_DEFAULT_CALLBACK_QUEUE_MODE, PCAP_THREAD_DEFAULT_CALLBACK_QUEUE_WAIT, 0, \
    0 \
}
#else
#define PCAP_THREAD_PCAPLIST_T_INIT { \
    0, 0, 0, 0, 0, 0, \
    0 \
}
#endif

struct pcap_thread_pcaplist {
    pcap_thread_pcaplist_t* next;
    char*                   name;
    pcap_t*                 pcap;
    void*                   user;
    int                     running;
    int                     is_offline;
#ifdef HAVE_PTHREAD
    pthread_t               thread;
    pthread_cond_t*         queue_cond;
    pthread_mutex_t*        queue_mutex;
    size_t                  queue_size;
    char*                   queue;
    struct pcap_pkthdr*     pkthdr;
    u_char*                 pkt;
    size_t                  read_pos;
    size_t                  write_pos;
    pcap_thread_callback_t  dropback;
    int                     snapshot;

    pthread_cond_t              callback_queue_cond;
    pthread_mutex_t             callback_queue_mutex;
    pcap_thread_queue_mode_t    callback_queue_mode;
    struct timeval              callback_queue_wait;
    int                         callback_queue_full;
#endif
    pcap_thread_callback_t  callback;
};

const char* pcap_thread_version_str(void);
int pcap_thread_version_major(void);
int pcap_thread_version_minor(void);
int pcap_thread_version_patch(void);

pcap_thread_t* pcap_thread_create(void);
void pcap_thread_free(pcap_thread_t* pcap_thread);

int pcap_thread_use_threads(const pcap_thread_t* pcap_thread);
int pcap_thread_set_use_threads(pcap_thread_t* pcap_thread, const int use_threads);
pcap_thread_queue_mode_t pcap_thread_queue_mode(const pcap_thread_t* pcap_thread);
int pcap_thread_set_queue_mode(pcap_thread_t* pcap_thread, const pcap_thread_queue_mode_t queue_mode);
struct timeval pcap_thread_queue_wait(const pcap_thread_t* pcap_thread);
int pcap_thread_set_queue_wait(pcap_thread_t* pcap_thread, const struct timeval queue_wait);
pcap_thread_queue_mode_t pcap_thread_callback_queue_mode(const pcap_thread_t* pcap_thread);
int pcap_thread_set_callback_queue_mode(pcap_thread_t* pcap_thread, const pcap_thread_queue_mode_t callback_queue_mode);
struct timeval pcap_thread_callback_queue_wait(const pcap_thread_t* pcap_thread);
int pcap_thread_set_callback_queue_wait(pcap_thread_t* pcap_thread, const struct timeval callback_queue_wait);
int pcap_thread_snapshot(const pcap_thread_t* pcap_thread);
int pcap_thread_snaplen(const pcap_thread_t* pcap_thread);
int pcap_thread_set_snaplen(pcap_thread_t* pcap_thread, const int snaplen);
int pcap_thread_promiscuous(const pcap_thread_t* pcap_thread);
int pcap_thread_set_promiscuous(pcap_thread_t* pcap_thread, const int promiscuous);
int pcap_thread_monitor(const pcap_thread_t* pcap_thread);
int pcap_thread_set_monitor(pcap_thread_t* pcap_thread, const int monitor);
int pcap_thread_timeout(const pcap_thread_t* pcap_thread);
int pcap_thread_set_timeout(pcap_thread_t* pcap_thread, const int timeout);
int pcap_thread_buffer_size(const pcap_thread_t* pcap_thread);
int pcap_thread_set_buffer_size(pcap_thread_t* pcap_thread, const int buffer_size);
int pcap_thread_timestamp_type(const pcap_thread_t* pcap_thread);
int pcap_thread_set_timestamp_type(pcap_thread_t* pcap_thread, const int timestamp_type);
int pcap_thread_timestamp_precision(const pcap_thread_t* pcap_thread);
int pcap_thread_set_timestamp_precision(pcap_thread_t* pcap_thread, const int timestamp_precision);
int pcap_thread_immediate_mode(const pcap_thread_t* pcap_thread);
int pcap_thread_set_immediate_mode(pcap_thread_t* pcap_thread, const int immediate_mode);
pcap_direction_t pcap_thread_direction(const pcap_thread_t* pcap_thread);
int pcap_thread_set_direction(pcap_thread_t* pcap_thread, pcap_direction_t direction);
const char* pcap_thread_filter(const pcap_thread_t* pcap_thread);
int pcap_thread_set_filter(pcap_thread_t* pcap_thread, const char* filter, const size_t filter_len);
int pcap_thread_filter_optimze(const pcap_thread_t* pcap_thread);
int pcap_thread_set_filter_optimize(pcap_thread_t* pcap_thread, const int filter_optimize);
bpf_u_int32 pcap_thread_filter_netmask(const pcap_thread_t* pcap_thread);
int pcap_thread_set_filter_netmask(pcap_thread_t* pcap_thread, const bpf_u_int32 filter_netmask);
struct timeval pcap_thread_timedrun(const pcap_thread_t* pcap_thread);
int pcap_thread_set_timedrun(pcap_thread_t* pcap_thread, struct timeval timedrun);

size_t pcap_thread_queue_size(const pcap_thread_t* pcap_thread);
int pcap_thread_set_queue_size(pcap_thread_t* pcap_thread, const size_t queue_size);

int pcap_thread_set_callback(pcap_thread_t* pcap_thread, pcap_thread_callback_t callback);
int pcap_thread_set_dropback(pcap_thread_t* pcap_thread, pcap_thread_callback_t dropback);

int pcap_thread_open(pcap_thread_t* pcap_thread, const char* device, void* user);
int pcap_thread_open_offline(pcap_thread_t* pcap_thread, const char* file, void* user);
int pcap_thread_add(pcap_thread_t* pcap_thread, const char* name, pcap_t* pcap, void* user);
int pcap_thread_close(pcap_thread_t* pcap_thread);

int pcap_thread_run(pcap_thread_t* pcap_thread);
int pcap_thread_next(pcap_thread_t* pcap_thread);
int pcap_thread_next_reset(pcap_thread_t* pcap_thread);
int pcap_thread_stop(pcap_thread_t* pcap_thread);

int pcap_thread_stats(pcap_thread_t* pcap_thread, pcap_thread_stats_callback_t callback, u_char* user);

int pcap_thread_status(const pcap_thread_t* pcap_thread);
const char* pcap_thread_errbuf(const pcap_thread_t* pcap_thread);
const char* pcap_thread_strerr(int error);

#ifdef __cplusplus
}
#endif

#endif /* __pcap_thread_h */
