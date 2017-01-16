/*
 * Author Jerry Lundström <jerry@dns-oarc.net>
 * Copyright (c) 2016-2017, OARC, Inc.
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

static pcap_thread_t _pcap_thread_defaults = PCAP_THREAD_T_INIT;

pcap_thread_t* pcap_thread_create(void) {
    pcap_thread_t* pcap_thread = calloc(1, sizeof(pcap_thread_t));
    if (pcap_thread) {
        memcpy(pcap_thread, &_pcap_thread_defaults, sizeof(pcap_thread_t));
    }

    return pcap_thread;
}

void pcap_thread_free(pcap_thread_t* pcap_thread) {
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
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
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
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    switch (queue_mode) {
        case PCAP_THREAD_QUEUE_MODE_COND:
            break;
        case PCAP_THREAD_QUEUE_MODE_YIELD:
        case PCAP_THREAD_QUEUE_MODE_WAIT:
        case PCAP_THREAD_QUEUE_MODE_DROP:
            return PCAP_THREAD_EOBSOLETE;
        default:
            return PCAP_THREAD_EINVAL;
    }

    pcap_thread->queue_mode = queue_mode;

    return PCAP_THREAD_OK;
}

struct timeval pcap_thread_queue_wait(const pcap_thread_t* pcap_thread) {
    static struct timeval tv = { 0, 0 };
    return tv;
}

int pcap_thread_set_queue_wait(pcap_thread_t* pcap_thread, const struct timeval queue_wait) {
    return PCAP_THREAD_EOBSOLETE;
}

pcap_thread_queue_mode_t pcap_thread_callback_queue_mode(const pcap_thread_t* pcap_thread) {
    return PCAP_THREAD_EOBSOLETE;
}

int pcap_thread_set_callback_queue_mode(pcap_thread_t* pcap_thread, const pcap_thread_queue_mode_t callback_queue_mode) {
    return PCAP_THREAD_EOBSOLETE;
}

struct timeval pcap_thread_callback_queue_wait(const pcap_thread_t* pcap_thread) {
    static struct timeval tv = { 0, 0 };
    return tv;
}

int pcap_thread_set_callback_queue_wait(pcap_thread_t* pcap_thread, const struct timeval callback_queue_wait) {
    return PCAP_THREAD_EOBSOLETE;
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
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
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
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
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
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
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
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
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
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
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
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->have_timestamp_type = 1;
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
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->have_timestamp_precision = 1;
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
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
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

int pcap_thread_set_direction(pcap_thread_t* pcap_thread, const pcap_direction_t direction) {
#ifdef HAVE_PCAP_DIRECTION_T
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->have_direction = 1;
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
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    if (pcap_thread->filter) {
        free(pcap_thread->filter);
    }

    pcap_thread->filter_len = filter_len;
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
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
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
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->filter_netmask = filter_netmask;

    return PCAP_THREAD_OK;
}

struct timeval pcap_thread_timedrun(const pcap_thread_t* pcap_thread) {
    if (!pcap_thread) {
        static struct timeval tv = { 0, 0 };
        return tv;
    }

    return pcap_thread->timedrun;
}

int pcap_thread_set_timedrun(pcap_thread_t* pcap_thread, const struct timeval timedrun) {
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->timedrun = timedrun;

    return PCAP_THREAD_OK;
}

struct timeval pcap_thread_timedrun_to(const pcap_thread_t* pcap_thread) {
    if (!pcap_thread) {
        static struct timeval tv = { 0, 0 };
        return tv;
    }

    return pcap_thread->timedrun_to;
}

int pcap_thread_set_timedrun_to(pcap_thread_t* pcap_thread, const struct timeval timedrun_to) {
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->timedrun_to = timedrun_to;

    return PCAP_THREAD_OK;
}

pcap_thread_activate_mode_t pcap_thread_activate_mode(const pcap_thread_t* pcap_thread) {
    if (!pcap_thread) {
        return PCAP_THREAD_DEFAULT_ACTIVATE_MODE;
    }

    return pcap_thread->activate_mode;
}

int pcap_thread_set_activate_mode(pcap_thread_t* pcap_thread, const pcap_thread_activate_mode_t activate_mode) {
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->activate_mode = activate_mode;

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
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->queue_size = queue_size;

    return PCAP_THREAD_OK;
}


int pcap_thread_set_callback(pcap_thread_t* pcap_thread, pcap_thread_callback_t callback) {
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->callback = callback;

    return PCAP_THREAD_OK;
}

int pcap_thread_set_dropback(pcap_thread_t* pcap_thread, pcap_thread_callback_t dropback) {
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->dropback = dropback;

    return PCAP_THREAD_OK;
}

/*
 * Open/Close
 */

static pcap_thread_pcaplist_t _pcaplist_defaults = PCAP_THREAD_PCAPLIST_T_INIT;

int pcap_thread_open(pcap_thread_t* pcap_thread, const char* device, void *user) {
    pcap_t*                 pcap;
    pcap_thread_pcaplist_t* pcaplist;
    int                     snapshot;

    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (!device) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    if (pcap_thread->errbuf[0]) {
        memset(pcap_thread->errbuf, 0, sizeof(pcap_thread->errbuf));
    }
    pcap_thread->status = 0;

    if (!(pcaplist = malloc(sizeof(pcap_thread_pcaplist_t)))) {
        return PCAP_THREAD_ENOMEM;
    }
    memcpy(pcaplist, &_pcaplist_defaults, sizeof(pcap_thread_pcaplist_t));
    if (!(pcaplist->name = strdup(device))) {
        free(pcaplist);
        return PCAP_THREAD_ENOMEM;
    }

#ifdef HAVE_PCAP_CREATE
    if (!(pcap = pcap_create(pcaplist->name, pcap_thread->errbuf))) {
        free(pcaplist->name);
        free(pcaplist);
        return PCAP_THREAD_EPCAP;
    }

    if (pcap_thread->monitor) {
        pcap_thread->status = pcap_can_set_rfmon(pcap);
        if (pcap_thread->status == 0) {
            pcap_close(pcap);
            free(pcaplist->name);
            free(pcaplist);
            return PCAP_THREAD_ENOMON;
        }
        if (pcap_thread->status != 1) {
            pcap_close(pcap);
            free(pcaplist->name);
            free(pcaplist);
            PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_can_set_rfmon()");
            return PCAP_THREAD_EPCAP;
        }
    }

#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
    if (pcap_thread->have_timestamp_precision && (pcap_thread->status = pcap_set_tstamp_precision(pcap, pcap_thread->timestamp_precision))) {
        pcap_close(pcap);
        free(pcaplist->name);
        free(pcaplist);
        PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_set_tstamp_precision()");
        return PCAP_THREAD_EPCAP;
    }
#endif
#ifdef HAVE_PCAP_SET_IMMEDIATE_MODE
    if (pcap_thread->immediate_mode && (pcap_thread->status = pcap_set_immediate_mode(pcap, 1))) {
        pcap_close(pcap);
        free(pcaplist->name);
        free(pcaplist);
        PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_set_immediate_mode()");
        return PCAP_THREAD_EPCAP;
    }
#endif

    if (pcap_thread->monitor && (pcap_thread->status = pcap_set_rfmon(pcap, 1))) {
        pcap_close(pcap);
        free(pcaplist->name);
        free(pcaplist);
        PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_set_rfmon()");
        return PCAP_THREAD_EPCAP;
    }
    if (pcap_thread->snaplen && (pcap_thread->status = pcap_set_snaplen(pcap, pcap_thread->snaplen))) {
        pcap_close(pcap);
        free(pcaplist->name);
        free(pcaplist);
        PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_set_snaplen()");
        return PCAP_THREAD_EPCAP;
    }
    if (pcap_thread->promiscuous && (pcap_thread->status = pcap_set_promisc(pcap, pcap_thread->promiscuous))) {
        pcap_close(pcap);
        free(pcaplist->name);
        free(pcaplist);
        PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_set_promisc()");
        return PCAP_THREAD_EPCAP;
    }
    if (pcap_thread->timeout && (pcap_thread->status = pcap_set_timeout(pcap, pcap_thread->timeout))) {
        pcap_close(pcap);
        free(pcaplist->name);
        free(pcaplist);
        PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_set_timeout()");
        return PCAP_THREAD_EPCAP;
    }
    if (pcap_thread->buffer_size && (pcap_thread->status = pcap_set_buffer_size(pcap, pcap_thread->buffer_size))) {
        pcap_close(pcap);
        free(pcaplist->name);
        free(pcaplist);
        PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_set_buffer_size()");
        return PCAP_THREAD_EPCAP;
    }

#ifdef HAVE_PCAP_SET_TSTAMP_TYPE
    if (pcap_thread->have_timestamp_type > -1 && (pcap_thread->status = pcap_set_tstamp_type(pcap, pcap_thread->timestamp_type))) {
        pcap_close(pcap);
        free(pcaplist->name);
        free(pcaplist);
        PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_set_tstamp_type()");
        return PCAP_THREAD_EPCAP;
    }
#endif

    if (pcap_thread->activate_mode == PCAP_THREAD_ACTIVATE_MODE_IMMEDIATE) {
        if ((pcap_thread->status = pcap_activate(pcap))) {
            pcap_close(pcap);
            free(pcaplist->name);
            free(pcaplist);
            PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_activate()");
            return PCAP_THREAD_EPCAP;
        }

#ifdef HAVE_PCAP_SETDIRECTION
#ifdef HAVE_PCAP_DIRECTION_T
        if (pcap_thread->have_direction && (pcap_thread->status = pcap_setdirection(pcap, pcap_thread->direction))) {
            pcap_close(pcap);
            free(pcaplist->name);
            free(pcaplist);
            PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_setdirection()");
            return PCAP_THREAD_EPCAP;
        }
#endif
#endif
    }
#else /* HAVE_PCAP_CREATE */
    if (!(pcap = pcap_open_live(pcaplist->name, pcap_thread->snaplen, pcap_thread->promiscuous, pcap_thread->timeout, pcap_thread->errbuf))) {
        free(pcaplist->name);
        free(pcaplist);
        return PCAP_THREAD_EPCAP;
    }
#endif

    if (pcap_thread->activate_mode == PCAP_THREAD_ACTIVATE_MODE_IMMEDIATE) {
        if (pcap_thread->filter) {
            if ((pcap_thread->status = pcap_compile(pcap, &(pcaplist->bpf), pcap_thread->filter, pcap_thread->filter_optimize, pcap_thread->filter_netmask))) {
                pcap_close(pcap);
                free(pcaplist->name);
                free(pcaplist);
                PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_compile()");
                return PCAP_THREAD_EPCAP;
            }
            pcaplist->have_bpf = 1;
            if ((pcap_thread->status = pcap_setfilter(pcap, &(pcaplist->bpf)))) {
                pcap_freecode(&(pcaplist->bpf));
                pcap_close(pcap);
                free(pcaplist->name);
                free(pcaplist);
                PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_setfilter()");
                return PCAP_THREAD_EPCAP;
            }
        }

        if ((snapshot = pcap_snapshot(pcap)) < 0) {
            pcap_thread->status = snapshot;
            if (pcaplist->have_bpf)
                pcap_freecode(&(pcaplist->bpf));
            pcap_close(pcap);
            free(pcaplist->name);
            free(pcaplist);
            PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_snapshot()");
            return PCAP_THREAD_EPCAP;
        }
        if (snapshot > pcap_thread->snapshot) {
            pcap_thread->snapshot = snapshot;
        }
    }

    pcaplist->pcap = pcap;
    pcaplist->user = user;
    if (pcap_thread->pcaplist) {
        pcaplist->next = pcap_thread->pcaplist;
    }
    pcap_thread->pcaplist = pcaplist;

    return PCAP_THREAD_OK;
}

int pcap_thread_open_offline(pcap_thread_t* pcap_thread, const char* file, void* user) {
    pcap_t*                 pcap;
    pcap_thread_pcaplist_t* pcaplist;
    int                     snapshot;

    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (!file) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    if (pcap_thread->errbuf[0]) {
        memset(pcap_thread->errbuf, 0, sizeof(pcap_thread->errbuf));
    }
    pcap_thread->status = 0;

    if (!(pcaplist = malloc(sizeof(pcap_thread_pcaplist_t)))) {
        return PCAP_THREAD_ENOMEM;
    }
    memcpy(pcaplist, &_pcaplist_defaults, sizeof(pcap_thread_pcaplist_t));
    pcaplist->is_offline = 1;
    if (!(pcaplist->name = strdup(file))) {
        free(pcaplist);
        return PCAP_THREAD_ENOMEM;
    }

#ifdef HAVE_PCAP_OPEN_OFFLINE_WITH_TSTAMP_PRECISION
    if (pcap_thread->have_timestamp_precision) {
        if (!(pcap = pcap_open_offline_with_tstamp_precision(pcaplist->name, pcap_thread->timestamp_precision, pcap_thread->errbuf))) {
            free(pcaplist->name);
            free(pcaplist);
            return PCAP_THREAD_EPCAP;
        }
    }
    else
#endif
    {
        if (!(pcap = pcap_open_offline(pcaplist->name, pcap_thread->errbuf))) {
            free(pcaplist->name);
            free(pcaplist);
            return PCAP_THREAD_EPCAP;
        }
    }

    if (pcap_thread->filter) {
        if ((pcap_thread->status = pcap_compile(pcap, &(pcaplist->bpf), pcap_thread->filter, pcap_thread->filter_optimize, pcap_thread->filter_netmask))) {
            pcap_close(pcap);
            free(pcaplist->name);
            free(pcaplist);
            PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_compile()");
            return PCAP_THREAD_EPCAP;
        }
        pcaplist->have_bpf = 1;
        if ((pcap_thread->status = pcap_setfilter(pcap, &(pcaplist->bpf)))) {
            pcap_freecode(&(pcaplist->bpf));
            pcap_close(pcap);
            free(pcaplist->name);
            free(pcaplist);
            PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_setfilter()");
            return PCAP_THREAD_EPCAP;
        }
    }

    if ((snapshot = pcap_snapshot(pcap)) < 0) {
        pcap_thread->status = snapshot;
        if (pcaplist->have_bpf)
            pcap_freecode(&(pcaplist->bpf));
        pcap_close(pcap);
        free(pcaplist->name);
        free(pcaplist);
        PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_snapshot()");
        return PCAP_THREAD_EPCAP;
    }
    if (snapshot > pcap_thread->snapshot) {
        pcap_thread->snapshot = snapshot;
    }

    pcaplist->pcap = pcap;
    pcaplist->user = user;
    if (pcap_thread->pcaplist) {
        pcaplist->next = pcap_thread->pcaplist;
    }
    pcap_thread->pcaplist = pcaplist;

    return PCAP_THREAD_OK;
}

int pcap_thread_add(pcap_thread_t* pcap_thread, const char* name, pcap_t* pcap, void* user) {
    (void)pcap_thread;
    (void)name;
    (void)pcap;
    (void)user;

    if (pcap_thread->errbuf[0]) {
        memset(pcap_thread->errbuf, 0, sizeof(pcap_thread->errbuf));
    }
    pcap_thread->status = 0;

    return PCAP_THREAD_EOBSOLETE;
}

int pcap_thread_activate(pcap_thread_t* pcap_thread) {
    pcap_thread_pcaplist_t* pcaplist;
    int snapshot;

    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    if (pcap_thread->errbuf[0]) {
        memset(pcap_thread->errbuf, 0, sizeof(pcap_thread->errbuf));
    }
    pcap_thread->status = 0;

    for (pcaplist = pcap_thread->pcaplist; pcaplist; pcaplist = pcaplist->next) {
        if (pcaplist->is_offline) {
            continue;
        }

#ifdef HAVE_PCAP_ACTIVATE
        if ((pcap_thread->status = pcap_activate(pcaplist->pcap))) {
            PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_activate()");
            return PCAP_THREAD_EPCAP;
        }
#endif

#ifdef HAVE_PCAP_SETDIRECTION
#ifdef HAVE_PCAP_DIRECTION_T
        if (pcap_thread->have_direction && (pcap_thread->status = pcap_setdirection(pcaplist->pcap, pcap_thread->direction))) {
            PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_setdirection()");
            return PCAP_THREAD_EPCAP;
        }
#endif
#endif

        if (pcap_thread->filter) {
            if (pcaplist->have_bpf)
                pcap_freecode(&(pcaplist->bpf));
            if ((pcap_thread->status = pcap_compile(pcaplist->pcap, &(pcaplist->bpf), pcap_thread->filter, pcap_thread->filter_optimize, pcap_thread->filter_netmask))) {
                PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_compile()");
                return PCAP_THREAD_EPCAP;
            }
            pcaplist->have_bpf = 1;
            if ((pcap_thread->status = pcap_setfilter(pcaplist->pcap, &(pcaplist->bpf)))) {
                PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_setfilter()");
                return PCAP_THREAD_EPCAP;
            }
        }

        if ((snapshot = pcap_snapshot(pcaplist->pcap)) < 0) {
            pcap_thread->status = snapshot;
            PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_snapshot()");
            return PCAP_THREAD_EPCAP;
        }
        if (snapshot > pcap_thread->snapshot) {
            pcap_thread->snapshot = snapshot;
        }
    }

    return PCAP_THREAD_OK;
}

int pcap_thread_close(pcap_thread_t* pcap_thread) {
    pcap_thread_pcaplist_t* pcaplist;

    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    while (pcap_thread->pcaplist) {
        pcaplist = pcap_thread->pcaplist;
        pcap_thread->pcaplist = pcaplist->next;

        if (pcaplist->pcap) {
            pcap_close(pcaplist->pcap);
        }
        if (pcaplist->have_bpf) {
            pcap_freecode(&(pcaplist->bpf));
        }
        if (pcaplist->name) {
            free(pcaplist->name);
        }
        free(pcaplist);
    }

#ifdef HAVE_PTHREAD
    if (pcap_thread->pkthdr) {
        free(pcap_thread->pkthdr);
        pcap_thread->pkthdr = 0;
    }
    if (pcap_thread->pkt) {
        free(pcap_thread->pkt);
        pcap_thread->pkt = 0;
    }
    if (pcap_thread->pcaplist_pkt) {
        free(pcap_thread->pcaplist_pkt);
        pcap_thread->pcaplist_pkt = 0;
    }
#endif
    if (pcap_thread->filter) {
        free(pcap_thread->filter);
        pcap_thread->filter = 0;
    }

    return PCAP_THREAD_OK;
}

/*
 * Engine
 */

#ifdef HAVE_PTHREAD
static void _callback(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* pkt) {
    pcap_thread_pcaplist_t* pcaplist;
    pcap_thread_t* pcap_thread;

    pthread_testcancel();

    if (!user) {
        return;
    }
    pcaplist = (pcap_thread_pcaplist_t*)user;

    if (!pcaplist->pcap_thread) {
        pcaplist->running = 0;
        return;
    }
    pcap_thread = pcaplist->pcap_thread;

    if (pkthdr->caplen > pcap_thread->snapshot) {
        if (pcap_thread->dropback) {
            pcap_thread->dropback(pcaplist->user, pkthdr, pkt, pcaplist->name, pcap_datalink(pcaplist->pcap));
        }
        return;
    }

    if (pthread_mutex_lock(&(pcap_thread->mutex))) {
        if (pcap_thread->dropback) {
            pcap_thread->dropback(pcaplist->user, pkthdr, pkt, pcaplist->name, pcap_datalink(pcaplist->pcap));
        }
        return;
    }

    while (pcaplist->running && pcap_thread->running) {
        if (pcap_thread->pkts < pcap_thread->queue_size) {
            pcap_thread->pcaplist_pkt[pcap_thread->write_pos] = pcaplist;
            memcpy(&(pcap_thread->pkthdr[pcap_thread->write_pos]), pkthdr, sizeof(struct pcap_pkthdr));
            memcpy(&(pcap_thread->pkt[pcap_thread->write_pos * pcap_thread->snapshot]), pkt, pkthdr->caplen);
            pcap_thread->write_pos++;
            if (pcap_thread->write_pos == pcap_thread->queue_size) {
                pcap_thread->write_pos = 0;
            }
            pcap_thread->pkts++;

            pthread_cond_signal(&(pcap_thread->have_packets));
            break;
        }

        if (pthread_cond_wait(&(pcap_thread->can_write), &(pcap_thread->mutex))) {
            pcaplist->running = 0;
            pcap_breakloop(pcaplist->pcap);
            return;
        }
        continue;
    }

    if (pthread_mutex_unlock(&(pcap_thread->mutex))) {
        pcaplist->running = 0;
        pcap_breakloop(pcaplist->pcap);
        return;
    }
}

static void* _thread(void* vp) {
    pcap_thread_pcaplist_t* pcaplist;
    int ret = 0;

    /*pthread_detach(pthread_self());*/

    if (!vp) {
        return 0;
    }
    pcaplist = (pcap_thread_pcaplist_t*)vp;

    if (!pcaplist->pcap_thread) {
        pcaplist->running = 0;
        return 0;
    }

    /*
     * pcap_loop() might return -2 to indicate pcap_breakloop() was called
     * but we do not need to act on that because either this thread has
     * been cancelled or running has been cleared
     */
    while (pcaplist->running) {
        pthread_testcancel();
        ret = pcap_loop(pcaplist->pcap, -1, _callback, (u_char*)pcaplist);
        if (ret == -1) {
            /* TODO: Store pcap_loop() error */
            break;
        }
        if (!ret)
            break;
    }

    pcaplist->running = 0;

    pthread_mutex_lock(&(pcaplist->pcap_thread->mutex));
    pthread_cond_signal(&(pcaplist->pcap_thread->have_packets));
    pthread_mutex_unlock(&(pcaplist->pcap_thread->mutex));

    return 0;
}
#endif

static void _callback2(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* pkt) {
    pcap_thread_pcaplist_t* pcaplist;

    if (!user) {
        return;
    }
    pcaplist = (pcap_thread_pcaplist_t*)user;

    if (!pcaplist->pcap_thread) {
        pcaplist->running = 0;
        return;
    }
    if (!pcaplist->pcap_thread->callback) {
        pcaplist->running = 0;
        return;
    }

    pcaplist->pcap_thread->callback(pcaplist->user, pkthdr, pkt, pcaplist->name, pcap_datalink(pcaplist->pcap));
}

int pcap_thread_run(pcap_thread_t* pcap_thread) {
    pcap_thread_pcaplist_t* pcaplist;
    int run = 1, timedrun = 0;
    struct timeval start = { 0, 0 };
    struct timespec end = { 0, 0 };

    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (!pcap_thread->pcaplist) {
        return PCAP_THREAD_NOPCAPS;
    }
    if (!pcap_thread->callback) {
        return PCAP_THREAD_NOCALLBACK;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    if (pcap_thread->errbuf[0]) {
        memset(pcap_thread->errbuf, 0, sizeof(pcap_thread->errbuf));
    }
    pcap_thread->status = 0;

    if (pcap_thread->timedrun.tv_sec || pcap_thread->timedrun.tv_usec) {
        timedrun = 1;
        if (gettimeofday(&start, 0)) {
            PCAP_THREAD_SET_ERRBUF(pcap_thread, "gettimeofday()");
            return PCAP_THREAD_ERRNO;
        }

        end.tv_sec = start.tv_sec + pcap_thread->timedrun.tv_sec
            + ( ( start.tv_usec + pcap_thread->timedrun.tv_usec ) / 1000000 );
        end.tv_nsec = ( ( start.tv_usec + pcap_thread->timedrun.tv_usec ) % 1000000 ) * 1000;
    }
    else if (pcap_thread->timedrun_to.tv_sec) {
        timedrun = 1;

        end.tv_sec = pcap_thread->timedrun_to.tv_sec;
        end.tv_nsec = pcap_thread->timedrun_to.tv_usec * 1000;
    }

#ifdef HAVE_PTHREAD
    if (pcap_thread->use_threads) {
        int err, all_offline;

        switch (pcap_thread->queue_mode) {
            case PCAP_THREAD_QUEUE_MODE_COND:
                if ((err = pthread_mutex_lock(&(pcap_thread->mutex)))) {
                    errno = err;
                    PCAP_THREAD_SET_ERRBUF(pcap_thread, "pthread_mutex_lock()");
                    return PCAP_THREAD_ERRNO;
                }
                break;
            case PCAP_THREAD_QUEUE_MODE_WAIT:
            case PCAP_THREAD_QUEUE_MODE_YIELD:
            case PCAP_THREAD_QUEUE_MODE_DROP:
                return PCAP_THREAD_EOBSOLETE;
            default:
                return PCAP_THREAD_EINVAL;
        }

        if (pcap_thread->running) {
            pthread_mutex_unlock(&(pcap_thread->mutex));
            return PCAP_THREAD_ERUNNING;
        }

        if (pcap_thread->pkthdr) {
            free(pcap_thread->pkthdr);
        }
        if (!(pcap_thread->pkthdr = calloc(pcap_thread->queue_size, sizeof(struct pcap_pkthdr)))) {
            pthread_mutex_unlock(&(pcap_thread->mutex));
            return PCAP_THREAD_ENOMEM;
        }

        if (pcap_thread->pkt) {
            free(pcap_thread->pkt);
        }
        if (!(pcap_thread->pkt = calloc(pcap_thread->queue_size, pcap_thread->snapshot))) {
            pthread_mutex_unlock(&(pcap_thread->mutex));
            return PCAP_THREAD_ENOMEM;
        }

        if (pcap_thread->pcaplist_pkt) {
            free(pcap_thread->pcaplist_pkt);
        }
        if (!(pcap_thread->pcaplist_pkt = calloc(pcap_thread->queue_size, sizeof(pcap_thread_pcaplist_t*)))) {
            pthread_mutex_unlock(&(pcap_thread->mutex));
            return PCAP_THREAD_ENOMEM;
        }

        pcap_thread->read_pos = 0;
        pcap_thread->write_pos = 0;
        pcap_thread->pkts = 0;

        all_offline = 1;
        for (pcaplist = pcap_thread->pcaplist; all_offline && pcaplist; pcaplist = pcaplist->next) {
            if (!pcaplist->is_offline) {
                all_offline = 0;
                break;
            }
        }

        pcap_thread->running = 1;
        err = PCAP_THREAD_OK;

        for (pcaplist = pcap_thread->pcaplist; pcaplist; pcaplist = pcaplist->next) {
            pcaplist->pcap_thread = pcap_thread;
            pcaplist->running = 1;

            if ((err = pthread_create(&(pcaplist->thread), 0, _thread, (void*)pcaplist))) {
                errno = err;
                err = PCAP_THREAD_ERRNO;
                PCAP_THREAD_SET_ERRBUF(pcap_thread, "pthread_create()");
                break;
            }
        }

        while (err == PCAP_THREAD_OK && run && pcap_thread->running) {
            while (pcap_thread->pkts) {
                if (!pcap_thread->pcaplist_pkt[pcap_thread->read_pos]) {
                    err = PCAP_THREAD_ENOPCAPLIST;
                    break;
                }

                pcap_thread->callback(
                    pcap_thread->pcaplist_pkt[pcap_thread->read_pos]->user,
                    &(pcap_thread->pkthdr[pcap_thread->read_pos]),
                    &(pcap_thread->pkt[pcap_thread->read_pos * pcap_thread->snapshot]),
                    pcap_thread->pcaplist_pkt[pcap_thread->read_pos]->name,
                    pcap_datalink(pcap_thread->pcaplist_pkt[pcap_thread->read_pos]->pcap)
                );

                pcap_thread->pcaplist_pkt[pcap_thread->read_pos] = 0;
                pcap_thread->read_pos++;
                if (pcap_thread->read_pos == pcap_thread->queue_size) {
                    pcap_thread->read_pos = 0;
                }
                pcap_thread->pkts--;
            }

            if (err != PCAP_THREAD_OK)
                break;

            if ((err = pthread_cond_broadcast(&(pcap_thread->can_write)))) {
                errno = err;
                err = PCAP_THREAD_ERRNO;
                PCAP_THREAD_SET_ERRBUF(pcap_thread, "pthread_cond_broadcast()");
                break;
            }

            run = 0;
            for (pcaplist = pcap_thread->pcaplist; pcaplist; pcaplist = pcaplist->next) {
                if (pcaplist->running) {
                    run = 1;
                }
            }
            if (!run)
                break;

            if (timedrun) {
                struct timeval now;

                if (gettimeofday(&now, 0)) {
                    err = PCAP_THREAD_ERRNO;
                    PCAP_THREAD_SET_ERRBUF(pcap_thread, "gettimeofday()");
                    break;
                }

                if (now.tv_sec > end.tv_sec
                    || (now.tv_sec == end.tv_sec && (now.tv_usec*1000) >= end.tv_nsec))
                {
                    break;
                }

                err = pthread_cond_timedwait(&(pcap_thread->have_packets), &(pcap_thread->mutex), &end);
                if (err == ETIMEDOUT) {
                    err = PCAP_THREAD_OK;
                }
                else if (err) {
                    errno = err;
                    err = PCAP_THREAD_ERRNO;
                    PCAP_THREAD_SET_ERRBUF(pcap_thread, "pthread_cond_timedwait()");
                    break;
                }
            }
            else {
                if ((err = pthread_cond_wait(&(pcap_thread->have_packets), &(pcap_thread->mutex)))) {
                    errno = err;
                    err = PCAP_THREAD_ERRNO;
                    PCAP_THREAD_SET_ERRBUF(pcap_thread, "pthread_cond_wait()");
                    break;
                }
            }
        }

        for (pcaplist = pcap_thread->pcaplist; pcaplist; pcaplist = pcaplist->next) {
            pcaplist->running = 0;
            pcap_breakloop(pcaplist->pcap);
            if (pcaplist->thread) {
                pthread_cancel(pcaplist->thread);
            }
        }

        pthread_mutex_unlock(&(pcap_thread->mutex));

        for (pcaplist = pcap_thread->pcaplist; pcaplist; pcaplist = pcaplist->next) {
            if (pcaplist->thread) {
                pthread_join(pcaplist->thread, 0);
                pcaplist->thread = 0;
            }
        }

        pcap_thread->running = 0;
        return err;
    }
    else
#endif
    {
        fd_set fds, rfds;
        int max_fd = 0;
        struct timeval t1, t2;

        pcap_thread->running = 1;

        FD_ZERO(&fds);
        for (pcaplist = pcap_thread->pcaplist; pcaplist; pcaplist = pcaplist->next) {
            int fd = pcap_get_selectable_fd(pcaplist->pcap);

            FD_SET(fd, &fds);
            if (fd > max_fd)
                max_fd = fd;

            if (!pcaplist->is_offline && (pcap_thread->status = pcap_setnonblock(pcaplist->pcap, 1, pcap_thread->errbuf))) {
                pcap_thread->running = 0;
                return PCAP_THREAD_EPCAP;
            }
            pcaplist->pcap_thread = pcap_thread;
            pcaplist->running = 1;
        }

        t1.tv_sec = pcap_thread->timeout / 1000;
        t1.tv_usec = (pcap_thread->timeout % 1000) * 1000;
        max_fd++;
        while (run) {
            rfds = fds;
            t2 = t1;
            if (timedrun) {
                struct timeval now;
                struct timeval diff;

                if (gettimeofday(&now, 0)) {
                    PCAP_THREAD_SET_ERRBUF(pcap_thread, "gettimeofday()");
                    pcap_thread->running = 0;
                    return PCAP_THREAD_ERRNO;
                }
                if (now.tv_sec > end.tv_sec
                    || (now.tv_sec == end.tv_sec && (now.tv_usec*1000) >= end.tv_nsec))
                {
                    break;
                }

                if (end.tv_sec > now.tv_sec) {
                    diff.tv_sec = end.tv_sec - now.tv_sec - 1;
                    diff.tv_usec = 1000000 - now.tv_usec;
                    diff.tv_usec += end.tv_nsec / 1000;
                    if (diff.tv_usec > 1000000) {
                        diff.tv_sec += diff.tv_usec / 1000000;
                        diff.tv_usec %= 1000000;
                    }
                }
                else {
                    diff.tv_sec = 0;
                    if (end.tv_sec == now.tv_sec && (end.tv_nsec/1000) > now.tv_usec) {
                        diff.tv_usec = (end.tv_nsec/1000) - now.tv_usec;
                    }
                    else {
                        diff.tv_usec = 0;
                    }
                }

                if (diff.tv_sec < t1.tv_sec || (diff.tv_sec == t1.tv_sec && diff.tv_usec < t1.tv_usec)) {
                    t2 = diff;
                }
            }
            if (select(max_fd, &rfds, 0, 0, &t2) == -1) {
                PCAP_THREAD_SET_ERRBUF(pcap_thread, "select()");
                pcap_thread->running = 0;
                return PCAP_THREAD_ERRNO;
            }

            run = 0;
            for (pcaplist = pcap_thread->pcaplist; pcaplist; pcaplist = pcaplist->next) {
                int packets;

                if (!pcaplist->running) {
                    continue;
                }
                else {
                    run = 1;
                }

                packets = pcap_dispatch(pcaplist->pcap, -1, _callback2, (u_char*)pcaplist);
                if (packets == -1) {
                    pcap_thread->status = -1;
                    PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_dispatch()");
                    pcap_thread->running = 0;
                    return PCAP_THREAD_EPCAP;
                }
                else if (packets == -2 || (pcaplist->is_offline && !packets)) {
                    pcaplist->running = 0;
                }
            }
        }

        pcap_thread->running = 0;
    }

    return PCAP_THREAD_OK;
}

int pcap_thread_next(pcap_thread_t* pcap_thread) {
    const u_char* pkt;
    struct pcap_pkthdr pkthdr;

    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }
    if (!pcap_thread->pcaplist) {
        return PCAP_THREAD_NOPCAPS;
    }

    if (pcap_thread->errbuf[0]) {
        memset(pcap_thread->errbuf, 0, sizeof(pcap_thread->errbuf));
    }
    pcap_thread->status = 0;

    if (!pcap_thread->step) {
        pcap_thread->step = pcap_thread->pcaplist;
    }
    if (!pcap_thread->step) {
        return PCAP_THREAD_OK;
    }

    if (!(pkt = pcap_next(pcap_thread->step->pcap, &pkthdr))) {
        pcap_thread->status = -1;
        PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_next()");
        return PCAP_THREAD_EPCAP;
    }
    pcap_thread->callback(pcap_thread->step->user, &pkthdr, pkt, pcap_thread->step->name, pcap_datalink(pcap_thread->step->pcap));
    pcap_thread->step = pcap_thread->step->next;

    return PCAP_THREAD_OK;
}

int pcap_thread_next_reset(pcap_thread_t* pcap_thread) {
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }
    if (!pcap_thread->pcaplist) {
        return PCAP_THREAD_NOPCAPS;
    }

    pcap_thread->step = 0;

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

    for (pcaplist = pcap_thread->pcaplist; pcaplist; pcaplist = pcaplist->next) {
        pcaplist->running = 0;
        pcap_breakloop(pcaplist->pcap);
    }
    pcap_thread->running = 0;

#ifdef HAVE_PTHREAD
    pthread_cond_broadcast(&(pcap_thread->have_packets));
    pthread_cond_broadcast(&(pcap_thread->can_write));
#endif

    return PCAP_THREAD_OK;
}

/*
 * Stats
 */

int pcap_thread_stats(pcap_thread_t* pcap_thread, pcap_thread_stats_callback_t callback, u_char* user) {
    pcap_thread_pcaplist_t* pcaplist;
    struct pcap_stat stats;

    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (!callback) {
        return PCAP_THREAD_NOCALLBACK;
    }
    if (!pcap_thread->pcaplist) {
        return PCAP_THREAD_NOPCAPS;
    }

    if (pcap_thread->errbuf[0]) {
        memset(pcap_thread->errbuf, 0, sizeof(pcap_thread->errbuf));
    }
    pcap_thread->status = 0;

    for (pcaplist = pcap_thread->pcaplist; pcaplist; pcaplist = pcaplist->next) {
        if ((pcap_thread->status = pcap_stats(pcaplist->pcap, &stats))) {
            PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_stats()");
            return PCAP_THREAD_EPCAP;
        }
        callback(user, &stats, pcaplist->name, pcap_datalink(pcaplist->pcap));
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

const char* pcap_thread_strerr(int error) {
    switch (error) {
        case PCAP_THREAD_OK:
            return 0;
        case PCAP_THREAD_EPCAP:
            return PCAP_THREAD_EPCAP_STR;
        case PCAP_THREAD_ENOMEM:
            return PCAP_THREAD_ENOMEM_STR;
        case PCAP_THREAD_ENOMON:
            return PCAP_THREAD_ENOMON_STR;
        case PCAP_THREAD_ENODIR:
            return PCAP_THREAD_ENODIR_STR;
        case PCAP_THREAD_EINVAL:
            return PCAP_THREAD_EINVAL_STR;
        case PCAP_THREAD_EWOULDBLOCK:
            return PCAP_THREAD_EWOULDBLOCK_STR;
        case PCAP_THREAD_NOPCAPS:
            return PCAP_THREAD_NOPCAPS_STR;
        case PCAP_THREAD_NOCALLBACK:
            return PCAP_THREAD_NOCALLBACK_STR;
        case PCAP_THREAD_ERRNO:
            return PCAP_THREAD_ERRNO_STR;
        case PCAP_THREAD_NOYIELD:
            return PCAP_THREAD_NOYIELD_STR;
        case PCAP_THREAD_EOBSOLETE:
            return PCAP_THREAD_EOBSOLETE_STR;
        case PCAP_THREAD_ERUNNING:
            return PCAP_THREAD_ERUNNING_STR;
        case PCAP_THREAD_ENOPCAPLIST:
            return PCAP_THREAD_ENOPCAPLIST_STR;
    }
    return "UNKNOWN";
}
