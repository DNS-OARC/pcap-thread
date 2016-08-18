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

#include "config.h"
#include "pcap_thread.h"

#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <errno.h>

/*
 * Version
 */

static const char* _version = PCAP_THREAD_VERSION_STR;
const char* pcap_thread_version_str(void) {
    return _version;
}

int pcap_thread_version_major(void) {
    return PCAP_THREAD_VERSION_MAJOR;
}

int pcap_thread_version_minor(void) {
    return PCAP_THREAD_VERSION_MINOR;
}

int pcap_thread_version_patch(void) {
    return PCAP_THREAD_VERSION_PATCH;
}

/*
 * Create/Free
 */

pcap_thread_t* pcap_thread_create(void) {
    pcap_thread_t* pcap_thread = calloc(1, sizeof(pcap_thread_t));
    if (pcap_thread) {
        static struct timeval queue_wait = PCAP_THREAD_DEFAULT_QUEUE_WAIT;

#ifdef HAVE_PTHREAD
        pcap_thread->queue_mode = PCAP_THREAD_QUEUE_MODE_COND;
        {
            int ret;

            if ((ret = pthread_cond_init(&(pcap_thread->queue_cond), 0))) {
                errno = ret;
                free(pcap_thread);
                return 0;
            }
            if ((ret = pthread_mutex_init(&(pcap_thread->queue_mutex), 0))) {
                errno = ret;
                free(pcap_thread);
                return 0;
            }
        }
#else
#ifdef HAVE_SCHED_YIELD
        pcap_thread->queue_mode = PCAP_THREAD_QUEUE_MODE_YIELD;
#else
        pcap_thread->queue_mode = PCAP_THREAD_QUEUE_MODE_WAIT;
#endif
#endif
        pcap_thread->queue_wait = queue_wait;
        pcap_thread->timeout = PCAP_THREAD_DEFAULT_TIMEOUT;
        pcap_thread->queue_size = PCAP_THREAD_DEFAULT_QUEUE_SIZE;
        pcap_thread->filter_optimize = 1;
    }

    return pcap_thread;
}

void pcap_thread_free(pcap_thread_t* pcap_thread) {
    pcap_thread_pcaplist_t* pcaplist;

    if (!pcap_thread) {
        return;
    }

    pcap_thread_close(pcap_thread);
    free(pcap_thread);
}

/*
 * Get/Set
 */

int pcap_thread_use_threads(const pcap_thread_t* pcap_thread) {
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->use_threads;
}

int pcap_thread_set_use_threads(pcap_thread_t* pcap_thread, const int use_threads) {
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }

    pcap_thread->use_threads = use_threads;

    return PCAP_THREAD_OK;
}

pcap_thread_queue_mode_t pcap_thread_queue_mode(const pcap_thread_t* pcap_thread) {
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->queue_mode;
}

int pcap_thread_set_queue_mode(pcap_thread_t* pcap_thread, const pcap_thread_queue_mode_t queue_mode) {
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }

#ifdef HAVE_PTHREAD
    switch (queue_mode) {
        case PCAP_THREAD_QUEUE_MODE_COND:
        case PCAP_THREAD_QUEUE_MODE_WAIT
            break;
        case PCAP_THREAD_QUEUE_MODE_YIELD:
#ifndef HAVE_SCHED_YIELD
            return PCAP_THREAD_NOSUPPORT;
#else
            break;
        default:
            return PCAP_THREAD_EINVAL;
    }
#endif

    pcap_thread->queue_mode = queue_mode;

    return PCAP_THREAD_OK;
}

struct timeval pcap_thread_queue_wait(const pcap_thread_t* pcap_thread) {
    if (!pcap_thread) {
        static struct timeval t = { 0, 0 };
        return t;
    }

    return pcap_thread->queue_wait;
}

int pcap_thread_set_queue_wait(pcap_thread_t* pcap_thread, const struct timeval queue_wait) {
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }

    pcap_thread->queue_wait = queue_wait;

    return PCAP_THREAD_OK;
}

int pcap_thread_snapshot(const pcap_thread_t* pcap_thread) {
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->snapshot;
}

int pcap_thread_snaplen(const pcap_thread_t* pcap_thread) {
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->snaplen;
}

int pcap_thread_set_snaplen(pcap_thread_t* pcap_thread, const int snaplen) {
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }

    pcap_thread->snaplen = snaplen;

    return PCAP_THREAD_OK;
}

int pcap_thread_promiscuous(const pcap_thread_t* pcap_thread) {
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->promiscuous;
}

int pcap_thread_set_promiscuous(pcap_thread_t* pcap_thread, const int promiscuous) {
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }

    pcap_thread->promiscuous = promiscuous;

    return PCAP_THREAD_OK;
}

int pcap_thread_monitor(const pcap_thread_t* pcap_thread) {
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->monitor;
}

int pcap_thread_set_monitor(pcap_thread_t* pcap_thread, const int monitor) {
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }

    pcap_thread->monitor = monitor;

    return PCAP_THREAD_OK;
}

int pcap_thread_timeout(const pcap_thread_t* pcap_thread) {
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->timeout;
}

int pcap_thread_set_timeout(pcap_thread_t* pcap_thread, const int timeout) {
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }

    pcap_thread->timeout = timeout;

    return PCAP_THREAD_OK;
}

int pcap_thread_buffer_size(const pcap_thread_t* pcap_thread) {
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->buffer_size;
}

int pcap_thread_set_buffer_size(pcap_thread_t* pcap_thread, const int buffer_size) {
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }

    pcap_thread->buffer_size = buffer_size;

    return PCAP_THREAD_OK;
}

int pcap_thread_timestamp_type(const pcap_thread_t* pcap_thread) {
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->timestamp_type;
}

int pcap_thread_set_timestamp_type(pcap_thread_t* pcap_thread, const int timestamp_type) {
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }

    pcap_thread->timestamp_type = timestamp_type;

    return PCAP_THREAD_OK;
}

int pcap_thread_timestamp_precision(const pcap_thread_t* pcap_thread) {
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->timestamp_precision;
}

int pcap_thread_set_timestamp_precision(pcap_thread_t* pcap_thread, const int timestamp_precision) {
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }

    pcap_thread->timestamp_precision = timestamp_precision;

    return PCAP_THREAD_OK;
}

int pcap_thread_immediate_mode(const pcap_thread_t* pcap_thread) {
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->immediate_mode;
}

int pcap_thread_set_immediate_mode(pcap_thread_t* pcap_thread, const int immediate_mode) {
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }

    pcap_thread->immediate_mode = immediate_mode;

    return PCAP_THREAD_OK;
}

pcap_direction_t pcap_thread_direction(const pcap_thread_t* pcap_thread) {
#ifdef HAVE_PCAP_DIRECTION_T
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->direction;
#else
    return 0;
#endif
}

int pcap_thread_set_direction(pcap_thread_t* pcap_thread, pcap_direction_t direction) {
#ifdef HAVE_PCAP_DIRECTION_T
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }

    pcap_thread->direction = direction;

    return PCAP_THREAD_OK;
#else
    return PCAP_THREAD_ENODIR;
#endif
}

const char* pcap_thread_filter(const pcap_thread_t* pcap_thread) {
    if (!pcap_thread) {
        return 0;
    }

    return pcap_thread->filter;
}

int pcap_thread_set_filter(pcap_thread_t* pcap_thread, const char* filter, const size_t filter_len) {
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (!filter) {
        return PCAP_THREAD_EINVAL;
    }
    if (!filter_len) {
        return PCAP_THREAD_EINVAL;
    }

    if (pcap_thread->filter) {
        free(pcap_thread->filter);
    }

    if ((pcap_thread->filter_len = filter_len) < 0) {
        pcap_thread->filter_len = strlen(filter);
    }
    pcap_thread->filter = strndup(filter, filter_len);

    return PCAP_THREAD_OK;
}

int pcap_thread_filter_optimze(const pcap_thread_t* pcap_thread) {
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->filter_optimize;
}

int pcap_thread_set_filter_optimize(pcap_thread_t* pcap_thread, const int filter_optimize) {
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }

    pcap_thread->filter_optimize = filter_optimize;

    return PCAP_THREAD_OK;
}

bpf_u_int32 pcap_thread_filter_netmask(const pcap_thread_t* pcap_thread) {
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->filter_netmask;
}

int pcap_thread_set_filter_netmask(pcap_thread_t* pcap_thread, const bpf_u_int32 filter_netmask) {
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }

    pcap_thread->filter_netmask = filter_netmask;

    return PCAP_THREAD_OK;
}

/*
 * Queue
 */

size_t pcap_thread_queue_size(const pcap_thread_t* pcap_thread) {
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->queue_size;
}

int pcap_thread_set_queue_size(pcap_thread_t* pcap_thread, const size_t queue_size) {
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (!queue_size) {
        return PCAP_THREAD_EINVAL;
    }

    pcap_thread->queue_size = queue_size;

    return PCAP_THREAD_OK;
}


int pcap_thread_set_callback(pcap_thread_t* pcap_thread, pcap_thread_callback_t callback) {
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }

    pcap_thread->callback = callback;

    return PCAP_THREAD_OK;
}

int pcap_thread_set_dropback(pcap_thread_t* pcap_thread, pcap_thread_callback_t dropback) {
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }

    pcap_thread->dropback = dropback;

    return PCAP_THREAD_OK;
}

/*
 * Open/Close
 */

int pcap_thread_open(pcap_thread_t* pcap_thread, const char* device, void *user) {
    pcap_t*                 pcap;
    pcap_thread_pcaplist_t* pcaplist;

    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (!device) {
        return PCAP_THREAD_EINVAL;
    }

    memset(pcap_thread->errbuf, 0, sizeof(pcap_thread->errbuf));
    pcap_thread->status = 0;
    if (!(pcaplist = calloc(1, sizeof(pcap_thread_pcaplist_t)))) {
        return PCAP_THREAD_ENOMEM;
    }

#ifdef HAVE_PCAP_CREATE
    if (!(pcap = pcap_create(device, pcap_thread->errbuf))) {
        free(pcaplist);
        return PCAP_THREAD_EPCAP;
    }

    if (pcap_thread->monitor) {
        pcap_thread->status = pcap_can_set_rfmon(pcap);
        if (pcap_thread->status == 0) {
            free(pcaplist);
            pcap_close(pcap);
            return PCAP_THREAD_ENOMON;
        }
        if (pcap_thread->status != 1) {
            free(pcaplist);
            pcap_close(pcap);
            return PCAP_THREAD_EPCAP;
        }
    }

#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
    if (pcap_thread->timestamp_precision && (pcap_thread->status = pcap_set_tstamp_precision(pcap, pcap_thread->timestamp_precision))) {
        free(pcaplist);
        pcap_close(pcap);
        return PCAP_THREAD_EPCAP;
    }
#endif
#ifdef HAVE_PCAP_SET_IMMEDIATE_MODE
    if (pcap_thread->immediate_mode && (pcap_thread->status = pcap_set_immediate_mode(pcap, 1))) {
        free(pcaplist);
        pcap_close(pcap);
        return PCAP_THREAD_EPCAP;
    }
#endif

    if (pcap_thread->monitor && (pcap_thread->status = pcap_set_rfmon(pcap, 1))) {
        free(pcaplist);
        pcap_close(pcap);
        return PCAP_THREAD_EPCAP;
    }
    if (pcap_thread->snaplen && (pcap_thread->status = pcap_set_snaplen(pcap, pcap_thread->snaplen))) {
        free(pcaplist);
        pcap_close(pcap);
        return PCAP_THREAD_EPCAP;
    }
    if (pcap_thread->promiscuous && (pcap_thread->status = pcap_set_promisc(pcap, pcap_thread->promiscuous))) {
        free(pcaplist);
        pcap_close(pcap);
        return PCAP_THREAD_EPCAP;
    }
    if (pcap_thread->timeout && (pcap_thread->status = pcap_set_timeout(pcap, pcap_thread->timeout))) {
        free(pcaplist);
        pcap_close(pcap);
        return PCAP_THREAD_EPCAP;
    }
    if (pcap_thread->buffer_size && (pcap_thread->status = pcap_set_buffer_size(pcap, pcap_thread->buffer_size))) {
        free(pcaplist);
        pcap_close(pcap);
        return PCAP_THREAD_EPCAP;
    }

#ifdef HAVE_PCAP_SET_TSTAMP_TYPE
    if (pcap_thread->buffer_size && (pcap_thread->status = pcap_set_buffer_size(pcap, pcap_thread->buffer_size))) {
        free(pcaplist);
        pcap_close(pcap);
        return PCAP_THREAD_EPCAP;
    }
#endif

    if ((pcap_thread->status = pcap_activate(pcap))) {
        free(pcaplist);
        pcap_close(pcap);
        return PCAP_THREAD_EPCAP;
    }
#ifdef HAVE_PCAP_SETDIRECTION
#ifndef HAVE_PCAP_DIRECTION_T
    if (pcap_thread->direction) {
        free(pcaplist);
        pcap_close(pcap);
        return PCAP_THREAD_ENODIR;
    }
#else
    if (pcap_thread->direction && (pcap_thread->status = pcap_setdirection(pcap, pcap_thread->direction))) {
        free(pcaplist);
        pcap_close(pcap);
        return PCAP_THREAD_EPCAP;
    }
#endif
#endif
#else /* HAVE_PCAP_CREATE */
    if (!(pcap = pcap_open_live(device, pcap_thread->snaplen, pcap_thread->promiscuous, pcap_thread->timeout, pcap_thread->errbuf))) {
        free(pcaplist);
        pcap_close(pcap);
        return PCAP_THREAD_EPCAP;
    }
#endif

    if (pcap_thread->filter) {
        if ((pcap_thread->status = pcap_compile(pcap, &(pcap_thread->bpf), pcap_thread->filter, pcap_thread->filter_optimize, pcap_thread->filter_netmask))) {
            free(pcaplist);
            pcap_close(pcap);
            return PCAP_THREAD_EPCAP;
        }
        if ((pcap_thread->status = pcap_setfilter(pcap, &(pcap_thread->bpf)))) {
            free(pcaplist);
            pcap_close(pcap);
            return PCAP_THREAD_EPCAP;
        }
    }

    pcaplist->pcap = pcap;
    pcaplist->user = user;
    if (pcap_thread->pcaplist) {
        pcaplist->next = pcap_thread->pcaplist;
    }
    pcap_thread->pcaplist = pcaplist;
    if (pcap_snapshot(pcap) > pcap_thread->snapshot) {
        pcap_thread->snapshot = pcap_snapshot(pcap);
    }

    return PCAP_THREAD_OK;
}

int pcap_thread_add(pcap_thread_t* pcap_thread, pcap_t* pcap, void* user) {
    pcap_thread_pcaplist_t* pcaplist;
    int nonblock;

    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (!pcap) {
        return PCAP_THREAD_EINVAL;
    }

    memset(pcap_thread->errbuf, 0, sizeof(pcap_thread->errbuf));
    pcap_thread->status = 0;

    nonblock = pcap_getnonblock(pcap, pcap_thread->errbuf);
    if (nonblock < 0) {
        return PCAP_THREAD_EPCAP;
    }
    if (nonblock > 0) {
        return PCAP_THREAD_EWOULDBLOCK;
    }

    if (!(pcaplist = calloc(1, sizeof(pcap_thread_pcaplist_t)))) {
        return PCAP_THREAD_ENOMEM;
    }

    pcaplist->pcap = pcap;
    pcaplist->user = user;
    if (pcap_thread->pcaplist) {
        pcaplist->next = pcap_thread->pcaplist;
    }
    pcap_thread->pcaplist = pcaplist;
    if (!pcap_thread->snapshot || pcap_snapshot(pcap) < pcap_thread->snapshot) {
        pcap_thread->snapshot = pcap_snapshot(pcap);
    }

    return PCAP_THREAD_OK;
}

int pcap_thread_close(pcap_thread_t* pcap_thread) {
    pcap_thread_pcaplist_t* pcaplist;

    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }

    while (pcap_thread->pcaplist) {
        pcaplist = pcap_thread->pcaplist;
        pcap_thread->pcaplist = pcaplist->next;

        if (pcaplist->pcap) {
            pcap_close(pcaplist->pcap);
        }
#ifdef HAVE_PTHREAD
        if (pcaplist->queue) {
            free(pcaplist->queue);
        }
        if (pcaplist->pkthdr) {
            free(pcaplist->pkthdr);
        }
        if (pcaplist->pkt) {
            free(pcaplist->pkt);
        }
#endif
        free(pcaplist);
    }

    if (pcap_thread->filter) {
        free(pcap_thread->filter);
        pcap_thread->filter = 0;
        pcap_freecode(&(pcap_thread->bpf));
        memset(&(pcap_thread->bpf), 0, sizeof(struct bpf_program));
    }

    return PCAP_THREAD_OK;
}

/*
 * Engine
 */

#ifdef HAVE_PTHREAD
#include <unistd.h>

void _callback(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* pkt) {
    pcap_thread_pcaplist_t* pcaplist;

    if (!user) {
        return;
    }
    pcaplist = (pcap_thread_pcaplist_t*)user;

    if (pcaplist->queue[pcaplist->write_pos]
        || pkthdr->caplen > pcaplist->snapshot)
    {
        if (pcaplist->dropback) {
            pcaplist->dropback(pcaplist->user, pkthdr, pkt);
        }
        return;
    }

    memcpy(&(pcaplist->pkthdr[pcaplist->write_pos]), pkthdr, sizeof(struct pcap_pkthdr));
    memcpy(&(pcaplist->pkt[pcaplist->write_pos]), pkt, pkthdr->caplen);
    pcaplist->queue[pcaplist->write_pos] = 1;
    pcaplist->write_pos++;
    if (pcaplist->write_pos == pcaplist->queue_size) {
        pcaplist->write_pos = 0;
    }
    if (pcaplist->queue_cond && pcaplist->queue_mutex) {
        pthread_mutex_lock(pcaplist->queue_mutex);
        pthread_cond_signal(pcaplist->queue_cond);
        pthread_mutex_unlock(pcaplist->queue_mutex);
    }
}

void* _thread(void* vp) {
    pcap_thread_pcaplist_t* pcaplist;
    int ret;

    if (!vp) {
        return 0;
    }
    pcaplist = (pcap_thread_pcaplist_t*)vp;

    ret = pcap_loop(pcaplist->pcap, -1, _callback, (u_char*)pcaplist);
    if (ret == -1) {
    }
    if (ret == -2) {
    }

    return 0;
}
#endif

int pcap_thread_run(pcap_thread_t* pcap_thread) {
    pcap_thread_pcaplist_t* pcaplist;
    int run = 1;

    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (!pcap_thread->pcaplist) {
        return PCAP_THREAD_NOPCAPS;
    }
    if (!pcap_thread->callback) {
        return PCAP_THREAD_NOCALLBACK;
    }

#ifdef HAVE_PTHREAD
    if (pcap_thread->use_threads) {
        int err;
        struct timeval t;

        switch (pcap_thread->queue_mode) {
            case PCAP_THREAD_QUEUE_MODE_COND:
                if ((err = pthread_mutex_lock(&(pcap_thread->queue_mutex)))) {
                    errno = err;
                    return PCAP_THREAD_ERRNO;
                }
                break;
            case PCAP_THREAD_QUEUE_MODE_WAIT:
                break;
            case PCAP_THREAD_QUEUE_MODE_YIELD:
#ifdef HAVE_SCHED_YIELD
                break;
#endif
            default:
                return PCAP_THREAD_EINVAL;
        }

        pcap_thread->queue_run = 1;
        for (pcaplist = pcap_thread->pcaplist; pcaplist; pcaplist = pcaplist->next) {
            if (pcaplist->queue) {
                free(pcaplist->queue);
                pcaplist->queue = 0;
            }
            if (pcaplist->pkthdr) {
                free(pcaplist->pkthdr);
                pcaplist->pkthdr = 0;
            }
            if (pcaplist->pkt) {
                free(pcaplist->pkt);
                pcaplist->pkt = 0;
            }
            pcaplist->queue_size = pcap_thread->queue_size;
            pcaplist->read_pos = 0;
            pcaplist->write_pos = 0;
            pcaplist->dropback = pcap_thread->dropback;
            pcaplist->snapshot = pcap_thread->snapshot;
            if (pcap_thread->queue_mode == PCAP_THREAD_QUEUE_MODE_COND) {
                pcaplist->queue_cond = &(pcap_thread->queue_cond);
                pcaplist->queue_mutex = &(pcap_thread->queue_mutex);
            }
            else {
                pcaplist->queue_cond = 0;
                pcaplist->queue_mutex = 0;
            }

            if (!(pcaplist->queue = calloc(pcaplist->queue_size, sizeof(char)))) {
                return PCAP_THREAD_ENOMEM;
            }
            if (!(pcaplist->pkthdr = calloc(pcaplist->queue_size, sizeof(struct pcap_pkthdr)))) {
                return PCAP_THREAD_ENOMEM;
            }
            if (!(pcaplist->pkt = calloc(pcaplist->queue_size, pcap_thread->snapshot))) {
                return PCAP_THREAD_ENOMEM;
            }

            if ((err = pthread_create(&(pcaplist->thread), 0, _thread, (void*)pcaplist))) {
                pcap_thread_stop(pcap_thread);
                errno = err;
                return PCAP_THREAD_ERRNO;
            }
        }

        while (run && pcap_thread->queue_run) {
            switch (pcap_thread->queue_mode) {
                case PCAP_THREAD_QUEUE_MODE_COND:
                    if ((err = pthread_cond_wait(&(pcap_thread->queue_cond), &(pcap_thread->queue_mutex)))) {
                        errno = err;
                        return PCAP_THREAD_ERRNO;
                    }
                    break;

                case PCAP_THREAD_QUEUE_MODE_WAIT:
                    t = pcap_thread->queue_wait;
                    select(1, NULL, NULL, NULL, &t);
                    break;

#ifdef HAVE_SCHED_YIELD
                case PCAP_THREAD_QUEUE_MODE_YIELD:
                    sched_yield();
                    break;
#endif
            }

            for (pcaplist = pcap_thread->pcaplist; pcaplist; pcaplist = pcaplist->next) {
                if (!pcaplist->thread) {
                    run = 0;
                }
                while (pcaplist->queue[pcaplist->read_pos]) {
                    pcap_thread->callback(pcaplist->user, &(pcaplist->pkthdr[pcaplist->read_pos]), &(pcaplist->pkt[pcaplist->read_pos]));

                    pcaplist->queue[pcaplist->read_pos] = 0;
                    pcaplist->read_pos++;
                    if (pcaplist->read_pos == pcaplist->queue_size) {
                        pcaplist->read_pos = 0;
                    }
                }
            }
        }
        if (pcap_thread->queue_mode == PCAP_THREAD_QUEUE_MODE_COND) {
            pthread_mutex_unlock(&(pcap_thread->queue_mutex));
        }
    }
    else
#endif
    {
        fd_set fds, rfds;
        int max_fd = 0;
        struct timeval t1, t2;

        memset(pcap_thread->errbuf, 0, sizeof(pcap_thread->errbuf));
        pcap_thread->status = 0;

        FD_ZERO(&fds);
        for (pcaplist = pcap_thread->pcaplist; pcaplist; pcaplist = pcaplist->next) {
            int fd = pcap_get_selectable_fd(pcaplist->pcap);

            FD_SET(fd, &fds);
            if (fd > max_fd)
                max_fd = fd;

            if ((pcap_thread->status = pcap_setnonblock(pcaplist->pcap, 1, pcap_thread->errbuf))) {
                return PCAP_THREAD_EPCAP;
            }
        }

        t1.tv_sec = pcap_thread->timeout / 1000;
        t1.tv_usec = (pcap_thread->timeout % 1000) * 1000;
        max_fd++;
        while (run) {
            rfds = fds;
            t2 = t1;
            if (select(max_fd, &rfds, 0, 0, &t2) == -1) {
                return PCAP_THREAD_ERRNO;
            }

            for (pcaplist = pcap_thread->pcaplist; pcaplist; pcaplist = pcaplist->next) {
                int packets = pcap_dispatch(pcaplist->pcap, -1, pcap_thread->callback, pcaplist->user);

                if (packets == -1) {
                    pcap_thread->status = -1;
                    return PCAP_THREAD_EPCAP;
                }
                else if (packets == -2) {
                    run = 0;
                }
            }
        }
    }

    return PCAP_THREAD_OK;
}

int pcap_thread_stop(pcap_thread_t* pcap_thread) {
    pcap_thread_pcaplist_t* pcaplist;

    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (!pcap_thread->pcaplist) {
        return PCAP_THREAD_NOPCAPS;
    }

#ifdef HAVE_PTHREAD
    if (pcap_thread->use_threads) {
        for (pcaplist = pcap_thread->pcaplist; pcaplist; pcaplist = pcaplist->next) {
            if (pcaplist->thread) {
                pthread_cancel(pcaplist->thread);
                pthread_join(pcaplist->thread, 0);
                pcaplist->thread = 0;
            }
        }
        pcap_thread->queue_run = 0;
        if (pcap_thread->queue_mode == PCAP_THREAD_QUEUE_MODE_COND) {
            pthread_cond_signal(&(pcap_thread->queue_cond));
        }
    }
    else
#endif
    {
        pcap_breakloop(pcaplist->pcap);
    }

    return PCAP_THREAD_OK;
}

/*
 * Error handling
 */

int pcap_thread_status(const pcap_thread_t* pcap_thread) {
    if (!pcap_thread) {
        return 0;
    }

    return pcap_thread->status;
}

const char* pcap_thread_errbuf(const pcap_thread_t* pcap_thread) {
    if (!pcap_thread) {
        return 0;
    }

    return pcap_thread->errbuf;
}
