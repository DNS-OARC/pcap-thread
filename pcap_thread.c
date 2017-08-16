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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>

/*
 * Forward declares for layer callbacks
 */

static void pcap_thread_callback(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* pkt, const char* name, int dlt);
static void pcap_thread_callback_linux_sll(u_char* user, pcap_thread_packet_t* packet, const u_char* payload, size_t length);
static void pcap_thread_callback_ether(u_char* user, pcap_thread_packet_t* packet, const u_char* payload, size_t length);
static void pcap_thread_callback_null(u_char* user, pcap_thread_packet_t* packet, const u_char* payload, size_t length);
static void pcap_thread_callback_loop(u_char* user, pcap_thread_packet_t* packet, const u_char* payload, size_t length);
static void pcap_thread_callback_ieee802(u_char* user, pcap_thread_packet_t* packet, const u_char* payload, size_t length);
static void pcap_thread_callback_gre(u_char* user, pcap_thread_packet_t* packet, const u_char* payload, size_t length);
static void pcap_thread_callback_ip(u_char* user, pcap_thread_packet_t* packet, const u_char* payload, size_t length);
static void pcap_thread_callback_ipv4(u_char* user, pcap_thread_packet_t* packet, const u_char* payload, size_t length);
static void pcap_thread_callback_ipv6(u_char* user, pcap_thread_packet_t* packet, const u_char* payload, size_t length);
static void pcap_thread_callback_udp(u_char* user, pcap_thread_packet_t* packet, const u_char* payload, size_t length);
static void pcap_thread_callback_tcp(u_char* user, pcap_thread_packet_t* packet, const u_char* payload, size_t length);

/*
 * Version
 */

static const char* _version = PCAP_THREAD_VERSION_STR;

const char* pcap_thread_version_str(void)
{
    return _version;
}

int pcap_thread_version_major(void)
{
    return PCAP_THREAD_VERSION_MAJOR;
}

int pcap_thread_version_minor(void)
{
    return PCAP_THREAD_VERSION_MINOR;
}

int pcap_thread_version_patch(void)
{
    return PCAP_THREAD_VERSION_PATCH;
}

/*
 * Create/Free
 */

static pcap_thread_t _pcap_thread_defaults = PCAP_THREAD_T_INIT;

pcap_thread_t* pcap_thread_create(void)
{
    pcap_thread_t* pcap_thread = calloc(1, sizeof(pcap_thread_t));
    if (pcap_thread) {
        memcpy(pcap_thread, &_pcap_thread_defaults, sizeof(pcap_thread_t));
    }

    return pcap_thread;
}

void pcap_thread_free(pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        return;
    }

    pcap_thread_close(pcap_thread);
    if (pcap_thread->filter) {
        free(pcap_thread->filter);
    }
    free(pcap_thread);
}

/*
 * Get/Set
 */

int pcap_thread_use_threads(const pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->use_threads;
}

int pcap_thread_set_use_threads(pcap_thread_t* pcap_thread, const int use_threads)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->use_threads = use_threads;

    return PCAP_THREAD_OK;
}

int pcap_thread_use_layers(const pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->use_layers;
}

int pcap_thread_set_use_layers(pcap_thread_t* pcap_thread, const int use_layers)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->use_layers = use_layers;

    return PCAP_THREAD_OK;
}

pcap_thread_queue_mode_t pcap_thread_queue_mode(const pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->queue_mode;
}

int pcap_thread_set_queue_mode(pcap_thread_t* pcap_thread, const pcap_thread_queue_mode_t queue_mode)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    switch (queue_mode) {
    case PCAP_THREAD_QUEUE_MODE_COND:
    case PCAP_THREAD_QUEUE_MODE_DIRECT:
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

struct timeval pcap_thread_queue_wait(const pcap_thread_t* pcap_thread)
{
    static struct timeval tv = { 0, 0 };
    return tv;
}

int pcap_thread_set_queue_wait(pcap_thread_t* pcap_thread, const struct timeval queue_wait)
{
    return PCAP_THREAD_EOBSOLETE;
}

pcap_thread_queue_mode_t pcap_thread_callback_queue_mode(const pcap_thread_t* pcap_thread)
{
    return PCAP_THREAD_EOBSOLETE;
}

int pcap_thread_set_callback_queue_mode(pcap_thread_t* pcap_thread, const pcap_thread_queue_mode_t callback_queue_mode)
{
    return PCAP_THREAD_EOBSOLETE;
}

struct timeval pcap_thread_callback_queue_wait(const pcap_thread_t* pcap_thread)
{
    static struct timeval tv = { 0, 0 };
    return tv;
}

int pcap_thread_set_callback_queue_wait(pcap_thread_t* pcap_thread, const struct timeval callback_queue_wait)
{
    return PCAP_THREAD_EOBSOLETE;
}

int pcap_thread_snapshot(const pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->snapshot;
}

int pcap_thread_snaplen(const pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->snaplen;
}

int pcap_thread_set_snaplen(pcap_thread_t* pcap_thread, const int snaplen)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->snaplen = snaplen;

    return PCAP_THREAD_OK;
}

int pcap_thread_promiscuous(const pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->promiscuous;
}

int pcap_thread_set_promiscuous(pcap_thread_t* pcap_thread, const int promiscuous)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->promiscuous = promiscuous;

    return PCAP_THREAD_OK;
}

int pcap_thread_monitor(const pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->monitor;
}

int pcap_thread_set_monitor(pcap_thread_t* pcap_thread, const int monitor)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->monitor = monitor;

    return PCAP_THREAD_OK;
}

int pcap_thread_timeout(const pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->timeout;
}

int pcap_thread_set_timeout(pcap_thread_t* pcap_thread, const int timeout)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->timeout = timeout;

    return PCAP_THREAD_OK;
}

int pcap_thread_buffer_size(const pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->buffer_size;
}

int pcap_thread_set_buffer_size(pcap_thread_t* pcap_thread, const int buffer_size)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->buffer_size = buffer_size;

    return PCAP_THREAD_OK;
}

int pcap_thread_timestamp_type(const pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->timestamp_type;
}

int pcap_thread_set_timestamp_type(pcap_thread_t* pcap_thread, const int timestamp_type)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->have_timestamp_type = 1;
    pcap_thread->timestamp_type      = timestamp_type;

    return PCAP_THREAD_OK;
}

int pcap_thread_timestamp_precision(const pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->timestamp_precision;
}

int pcap_thread_set_timestamp_precision(pcap_thread_t* pcap_thread, const int timestamp_precision)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->have_timestamp_precision = 1;
    pcap_thread->timestamp_precision      = timestamp_precision;

    return PCAP_THREAD_OK;
}

int pcap_thread_immediate_mode(const pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->immediate_mode;
}

int pcap_thread_set_immediate_mode(pcap_thread_t* pcap_thread, const int immediate_mode)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->immediate_mode = immediate_mode;

    return PCAP_THREAD_OK;
}

pcap_direction_t pcap_thread_direction(const pcap_thread_t* pcap_thread)
{
#ifdef HAVE_PCAP_DIRECTION_T
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->direction;
#else
    return 0;
#endif
}

int pcap_thread_set_direction(pcap_thread_t* pcap_thread, const pcap_direction_t direction)
{
#ifdef HAVE_PCAP_DIRECTION_T
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->have_direction = 1;
    pcap_thread->direction      = direction;

    return PCAP_THREAD_OK;
#else
    return PCAP_THREAD_ENODIR;
#endif
}

const char* pcap_thread_filter(const pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        return 0;
    }

    return pcap_thread->filter;
}

int pcap_thread_set_filter(pcap_thread_t* pcap_thread, const char* filter, const size_t filter_len)
{
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
    if (!(pcap_thread->filter = strndup(filter, filter_len))) {
        return PCAP_THREAD_ENOMEM;
    }
    pcap_thread->filter_len = filter_len;

    return PCAP_THREAD_OK;
}

int pcap_thread_clear_filter(pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    if (pcap_thread->filter) {
        free(pcap_thread->filter);
        pcap_thread->filter     = 0;
        pcap_thread->filter_len = 0;
    }

    return PCAP_THREAD_OK;
}

int pcap_thread_filter_errno(const pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->filter_errno;
}

int pcap_thread_filter_optimze(const pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->filter_optimize;
}

int pcap_thread_set_filter_optimize(pcap_thread_t* pcap_thread, const int filter_optimize)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->filter_optimize = filter_optimize;

    return PCAP_THREAD_OK;
}

bpf_u_int32 pcap_thread_filter_netmask(const pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->filter_netmask;
}

int pcap_thread_set_filter_netmask(pcap_thread_t* pcap_thread, const bpf_u_int32 filter_netmask)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->filter_netmask = filter_netmask;

    return PCAP_THREAD_OK;
}

struct timeval pcap_thread_timedrun(const pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        static struct timeval tv = { 0, 0 };
        return tv;
    }

    return pcap_thread->timedrun;
}

int pcap_thread_set_timedrun(pcap_thread_t* pcap_thread, const struct timeval timedrun)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->timedrun = timedrun;

    return PCAP_THREAD_OK;
}

struct timeval pcap_thread_timedrun_to(const pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        static struct timeval tv = { 0, 0 };
        return tv;
    }

    return pcap_thread->timedrun_to;
}

int pcap_thread_set_timedrun_to(pcap_thread_t* pcap_thread, const struct timeval timedrun_to)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->timedrun_to = timedrun_to;

    return PCAP_THREAD_OK;
}

pcap_thread_activate_mode_t pcap_thread_activate_mode(const pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        return PCAP_THREAD_DEFAULT_ACTIVATE_MODE;
    }

    return pcap_thread->activate_mode;
}

int pcap_thread_set_activate_mode(pcap_thread_t* pcap_thread, const pcap_thread_activate_mode_t activate_mode)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->activate_mode = activate_mode;

    return PCAP_THREAD_OK;
}

int pcap_thread_was_stopped(const pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }

    return pcap_thread->was_stopped;
}

/*
 * Queue
 */

size_t pcap_thread_queue_size(const pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        return -1;
    }

    return pcap_thread->queue_size;
}

int pcap_thread_set_queue_size(pcap_thread_t* pcap_thread, const size_t queue_size)
{
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

int pcap_thread_set_callback(pcap_thread_t* pcap_thread, pcap_thread_callback_t callback)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->callback = callback;

    return PCAP_THREAD_OK;
}

int pcap_thread_set_dropback(pcap_thread_t* pcap_thread, pcap_thread_callback_t dropback)
{
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
 * Layers
 */

int pcap_thread_set_callback_linux_sll(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_linux_sll)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->callback_ether
        || pcap_thread->callback_null
        || pcap_thread->callback_loop
        || pcap_thread->callback_ieee802
        || pcap_thread->callback_gre
        || pcap_thread->callback_ip
        || pcap_thread->callback_ipv4
        || pcap_thread->callback_ipv6
        || pcap_thread->callback_udp
        || pcap_thread->callback_tcp) {
        return PCAP_THREAD_ELAYERCB;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->callback_linux_sll = callback_linux_sll;

    return PCAP_THREAD_OK;
}

int pcap_thread_set_callback_ether(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_ether)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->callback_linux_sll
        || pcap_thread->callback_null
        || pcap_thread->callback_loop
        || pcap_thread->callback_ieee802
        || pcap_thread->callback_gre
        || pcap_thread->callback_ip
        || pcap_thread->callback_ipv4
        || pcap_thread->callback_ipv6
        || pcap_thread->callback_udp
        || pcap_thread->callback_tcp) {
        return PCAP_THREAD_ELAYERCB;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->callback_ether = callback_ether;

    return PCAP_THREAD_OK;
}

int pcap_thread_set_callback_null(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_null)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->callback_linux_sll
        || pcap_thread->callback_ether
        || pcap_thread->callback_loop
        || pcap_thread->callback_ieee802
        || pcap_thread->callback_gre
        || pcap_thread->callback_ip
        || pcap_thread->callback_ipv4
        || pcap_thread->callback_ipv6
        || pcap_thread->callback_udp
        || pcap_thread->callback_tcp) {
        return PCAP_THREAD_ELAYERCB;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->callback_null = callback_null;

    return PCAP_THREAD_OK;
}

int pcap_thread_set_callback_loop(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_loop)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->callback_linux_sll
        || pcap_thread->callback_ether
        || pcap_thread->callback_null
        || pcap_thread->callback_ieee802
        || pcap_thread->callback_gre
        || pcap_thread->callback_ip
        || pcap_thread->callback_ipv4
        || pcap_thread->callback_ipv6
        || pcap_thread->callback_udp
        || pcap_thread->callback_tcp) {
        return PCAP_THREAD_ELAYERCB;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->callback_loop = callback_loop;

    return PCAP_THREAD_OK;
}

int pcap_thread_set_callback_ieee802(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_ieee802)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->callback_linux_sll
        || pcap_thread->callback_ether
        || pcap_thread->callback_null
        || pcap_thread->callback_loop
        || pcap_thread->callback_gre
        || pcap_thread->callback_ip
        || pcap_thread->callback_ipv4
        || pcap_thread->callback_ipv6
        || pcap_thread->callback_udp
        || pcap_thread->callback_tcp) {
        return PCAP_THREAD_ELAYERCB;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->callback_ieee802 = callback_ieee802;

    return PCAP_THREAD_OK;
}

int pcap_thread_set_callback_gre(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_gre)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->callback_linux_sll
        || pcap_thread->callback_ether
        || pcap_thread->callback_null
        || pcap_thread->callback_loop
        || pcap_thread->callback_ieee802
        || pcap_thread->callback_ip
        || pcap_thread->callback_ipv4
        || pcap_thread->callback_ipv6
        || pcap_thread->callback_udp
        || pcap_thread->callback_tcp) {
        return PCAP_THREAD_ELAYERCB;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->callback_gre = callback_gre;

    return PCAP_THREAD_OK;
}

int pcap_thread_set_callback_ip(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_ip)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->callback_linux_sll
        || pcap_thread->callback_ether
        || pcap_thread->callback_null
        || pcap_thread->callback_loop
        || pcap_thread->callback_ieee802
        || pcap_thread->callback_gre
        || pcap_thread->callback_ipv4
        || pcap_thread->callback_ipv6
        || pcap_thread->callback_udp
        || pcap_thread->callback_tcp) {
        return PCAP_THREAD_ELAYERCB;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->callback_ip = callback_ip;

    return PCAP_THREAD_OK;
}

int pcap_thread_set_callback_ipv4(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_ipv4)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->callback_linux_sll
        || pcap_thread->callback_ether
        || pcap_thread->callback_null
        || pcap_thread->callback_loop
        || pcap_thread->callback_ieee802
        || pcap_thread->callback_gre
        || pcap_thread->callback_ip
        || pcap_thread->callback_udp
        || pcap_thread->callback_tcp) {
        return PCAP_THREAD_ELAYERCB;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->callback_ipv4 = callback_ipv4;

    return PCAP_THREAD_OK;
}

int pcap_thread_set_callback_ipv6(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_ipv6)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->callback_linux_sll
        || pcap_thread->callback_ether
        || pcap_thread->callback_null
        || pcap_thread->callback_loop
        || pcap_thread->callback_ieee802
        || pcap_thread->callback_gre
        || pcap_thread->callback_ip
        || pcap_thread->callback_udp
        || pcap_thread->callback_tcp) {
        return PCAP_THREAD_ELAYERCB;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->callback_ipv6 = callback_ipv6;

    return PCAP_THREAD_OK;
}

int pcap_thread_set_callback_udp(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_udp)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->callback_linux_sll
        || pcap_thread->callback_ether
        || pcap_thread->callback_null
        || pcap_thread->callback_loop
        || pcap_thread->callback_ieee802
        || pcap_thread->callback_gre
        || pcap_thread->callback_ip
        || pcap_thread->callback_ipv4
        || pcap_thread->callback_ipv6) {
        return PCAP_THREAD_ELAYERCB;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->callback_udp = callback_udp;

    return PCAP_THREAD_OK;
}

int pcap_thread_set_callback_tcp(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_tcp)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->callback_linux_sll
        || pcap_thread->callback_ether
        || pcap_thread->callback_null
        || pcap_thread->callback_loop
        || pcap_thread->callback_ieee802
        || pcap_thread->callback_gre
        || pcap_thread->callback_ip
        || pcap_thread->callback_ipv4
        || pcap_thread->callback_ipv6) {
        return PCAP_THREAD_ELAYERCB;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->callback_tcp = callback_tcp;

    return PCAP_THREAD_OK;
}

int pcap_thread_set_callback_invalid(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_invalid)
{
    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    pcap_thread->callback_invalid = callback_invalid;

    return PCAP_THREAD_OK;
}

#define need4x2(v1, v2, p, l) \
    if (l < 1) {              \
        break;                \
    }                         \
    v1 = (*p) >> 4;           \
    v2 = (*p) & 0xf;          \
    p += 1;                   \
    l -= 1

#define need8(v, p, l) \
    if (l < 1) {       \
        break;         \
    }                  \
    v = *p;            \
    p += 1;            \
    l -= 1

#define need16(v, p, l)       \
    if (l < 2) {              \
        break;                \
    }                         \
    v = (*p << 8) + *(p + 1); \
    p += 2;                   \
    l -= 2

#define need32(v, p, l)                                             \
    if (l < 4) {                                                    \
        break;                                                      \
    }                                                               \
    v = (*p << 24) + (*(p + 1) << 16) + (*(p + 2) << 8) + *(p + 3); \
    p += 4;                                                         \
    l -= 4

#define needxb(b, x, p, l) \
    if (l < x) {           \
        break;             \
    }                      \
    memcpy(b, p, x);       \
    p += x;                \
    l -= x

#define advancexb(x, p, l) \
    if (l < x) {           \
        break;             \
    }                      \
    p += x;                \
    l -= x

#if 0
#define layer_trace(msg) printf("LT %s:%d: " msg "\n", __FILE__, __LINE__)
#define layer_tracef(msg, args...) printf("LT %s:%d: " msg "\n", __FILE__, __LINE__, args)
#else
#define layer_trace(msg)
#define layer_tracef(msg, args...)
#endif

static void pcap_thread_callback(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* pkt, const char* name, int dlt)
{
    pcap_thread_pcaplist_t* pcaplist = (pcap_thread_pcaplist_t*)user;
    size_t                  length;
    pcap_thread_packet_t    packet;
    const u_char*           orig = pkt;
    size_t                  origlength;

    if (!pcaplist) {
        return;
    }
    if (!pcaplist->pcap_thread) {
        return;
    }
    if (!pkthdr) {
        return;
    }
    if (!pkt) {
        return;
    }
    if (!name) {
        return;
    }

    memset(&packet, 0, sizeof(packet));
    packet.name        = name;
    packet.dlt         = dlt;
    packet.pkthdr      = *pkthdr;
    packet.have_pkthdr = 1;
    length             = pkthdr->caplen;
    origlength         = length;

    layer_tracef("packet, length %lu", length);

    switch (dlt) {
    case DLT_NULL:
        layer_trace("dlt_null");
        {
            uint8_t hdr[4];

            packet.state = PCAP_THREAD_PACKET_INVALID_NULL;
            need8(hdr[0], pkt, length);
            need8(hdr[1], pkt, length);
            need8(hdr[2], pkt, length);
            need8(hdr[3], pkt, length);
            packet.state = PCAP_THREAD_PACKET_OK;

            /*
                 * The header for null is in host byte order but may not be
                 * in the same endian as host if coming from a savefile
                 */

            if (pcaplist->is_offline && pcap_is_swapped(pcaplist->pcap)) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
                packet.nullhdr.family = hdr[3] + (hdr[2] << 8) + (hdr[1] << 16) + (hdr[0] << 24);
#elif __BYTE_ORDER == __BIG_ENDIAN
                packet.nullhdr.family = hdr[0] + (hdr[1] << 8) + (hdr[2] << 16) + (hdr[3] << 24);
#else
#error "Please fix <endian.h>"
#endif
            } else {
#if __BYTE_ORDER == __LITTLE_ENDIAN
                packet.nullhdr.family = hdr[0] + (hdr[1] << 8) + (hdr[2] << 16) + (hdr[3] << 24);
#elif __BYTE_ORDER == __BIG_ENDIAN
                packet.nullhdr.family = hdr[3] + (hdr[2] << 8) + (hdr[1] << 16) + (hdr[0] << 24);
#else
#error "Please fix <endian.h>"
#endif
            }
            packet.have_nullhdr = 1;

            if (pcaplist->pcap_thread->callback_null)
                pcaplist->pcap_thread->callback_null(pcaplist->user, &packet, pkt, length);
            else
                pcap_thread_callback_null((void*)pcaplist, &packet, pkt, length);
            return;
        }
        break;

    case DLT_EN10MB:
        layer_trace("dlt_en10mb");
        packet.state = PCAP_THREAD_PACKET_INVALID_ETHER;
        needxb(packet.ethhdr.ether_dhost, sizeof(packet.ethhdr.ether_dhost), pkt, length);
        needxb(packet.ethhdr.ether_shost, sizeof(packet.ethhdr.ether_shost), pkt, length);
        need16(packet.ethhdr.ether_type, pkt, length);
        packet.state       = PCAP_THREAD_PACKET_OK;
        packet.have_ethhdr = 1;

        if (pcaplist->pcap_thread->callback_ether)
            pcaplist->pcap_thread->callback_ether(pcaplist->user, &packet, pkt, length);
        else
            pcap_thread_callback_ether((void*)pcaplist, &packet, pkt, length);
        return;

    case DLT_LOOP:
        layer_trace("dlt_loop");
        packet.state = PCAP_THREAD_PACKET_INVALID_LOOP;
        need32(packet.loophdr.family, pkt, length);
        packet.state        = PCAP_THREAD_PACKET_OK;
        packet.have_loophdr = 1;

        if (pcaplist->pcap_thread->callback_loop)
            pcaplist->pcap_thread->callback_loop(pcaplist->user, &packet, pkt, length);
        else
            pcap_thread_callback_loop((void*)pcaplist, &packet, pkt, length);
        return;

    case DLT_RAW:
#ifdef DLT_IPV4
    case DLT_IPV4:
#endif
#ifdef DLT_IPV6
    case DLT_IPV6:
#endif
        layer_trace("dlt_raw/ipv4/ipv6");
        if (pcaplist->pcap_thread->callback_ip)
            pcaplist->pcap_thread->callback_ip(pcaplist->user, &packet, pkt, length);
        else
            pcap_thread_callback_ip((void*)pcaplist, &packet, pkt, length);
        return;

    case DLT_LINUX_SLL:
        layer_trace("dlt_linux_sll");
        packet.state = PCAP_THREAD_PACKET_INVALID_LINUX_SLL;
        need16(packet.linux_sll.packet_type, pkt, length);
        need16(packet.linux_sll.arp_hardware, pkt, length);
        need16(packet.linux_sll.link_layer_address_length, pkt, length);
        needxb(packet.linux_sll.link_layer_address, 8, pkt, length);
        need16(packet.linux_sll.ether_type, pkt, length);
        packet.state          = PCAP_THREAD_PACKET_OK;
        packet.have_linux_sll = 1;

        if (pcaplist->pcap_thread->callback_linux_sll)
            pcaplist->pcap_thread->callback_linux_sll(pcaplist->user, &packet, pkt, length);
        else
            pcap_thread_callback_linux_sll((void*)pcaplist, &packet, pkt, length);
        return;

    /* TODO: These might be interesting to implement
        case DLT_IPNET:
        case DLT_PKTAP:
        */

    default:
        packet.state = PCAP_THREAD_PACKET_UNSUPPORTED;
        break;
    }

    if (pcaplist->pcap_thread->callback_invalid) {
        if (packet.state == PCAP_THREAD_PACKET_OK)
            packet.state = PCAP_THREAD_PACKET_INVALID;
        pcaplist->pcap_thread->callback_invalid(pcaplist->user, &packet, orig, origlength);
    }
}

static void pcap_thread_callback_linux_sll(u_char* user, pcap_thread_packet_t* packet, const u_char* payload, size_t length)
{
    pcap_thread_pcaplist_t* pcaplist   = (pcap_thread_pcaplist_t*)user;
    const u_char*           orig       = payload;
    size_t                  origlength = length;

    if (!pcaplist) {
        return;
    }
    if (!pcaplist->pcap_thread) {
        return;
    }
    if (!packet) {
        return;
    }
    if (!payload) {
        return;
    }
    if (!length) {
        return;
    }

    if (packet->have_linux_sll) {
        layer_trace("have_linux_sll");
        switch (packet->linux_sll.ether_type) {
        case 0x8100: /* 802.1q */
        case 0x88a8: /* 802.1ad */
        case 0x9100: /* 802.1 QinQ non-standard */
            if (packet->have_ieee802hdr)
                break;

            {
                uint16_t tci;

                packet->state = PCAP_THREAD_PACKET_INVALID_IEEE802;
                need16(tci, payload, length);
                packet->ieee802hdr.pcp = (tci & 0xe000) >> 13;
                packet->ieee802hdr.dei = (tci & 0x1000) >> 12;
                packet->ieee802hdr.vid = tci & 0x0fff;
                need16(packet->ieee802hdr.ether_type, payload, length);
                packet->state           = PCAP_THREAD_PACKET_OK;
                packet->have_ieee802hdr = 1;
            }

            if (pcaplist->pcap_thread->callback_ieee802)
                pcaplist->pcap_thread->callback_ieee802(pcaplist->user, packet, payload, length);
            else
                pcap_thread_callback_ieee802((void*)pcaplist, packet, payload, length);
            return;

        case ETHERTYPE_IP:
        case ETHERTYPE_IPV6:
            if (pcaplist->pcap_thread->callback_ip)
                pcaplist->pcap_thread->callback_ip(pcaplist->user, packet, payload, length);
            else
                pcap_thread_callback_ip((void*)pcaplist, packet, payload, length);
            return;

        default:
            packet->state = PCAP_THREAD_PACKET_UNSUPPORTED;
            break;
        }
    }

    if (pcaplist->pcap_thread->callback_invalid) {
        if (packet->state == PCAP_THREAD_PACKET_OK)
            packet->state = PCAP_THREAD_PACKET_INVALID;
        pcaplist->pcap_thread->callback_invalid(pcaplist->user, packet, orig, origlength);
    }
}

static void pcap_thread_callback_ether(u_char* user, pcap_thread_packet_t* packet, const u_char* payload, size_t length)
{
    pcap_thread_pcaplist_t* pcaplist   = (pcap_thread_pcaplist_t*)user;
    const u_char*           orig       = payload;
    size_t                  origlength = length;

    if (!pcaplist) {
        return;
    }
    if (!pcaplist->pcap_thread) {
        return;
    }
    if (!packet) {
        return;
    }
    if (!payload) {
        return;
    }
    if (!length) {
        return;
    }

    if (packet->have_ethhdr) {
        layer_trace("have_ethhdr");
        switch (packet->ethhdr.ether_type) {
        case 0x8100: /* 802.1q */
        case 0x88a8: /* 802.1ad */
        case 0x9100: /* 802.1 QinQ non-standard */
            if (packet->have_ieee802hdr)
                break;

            {
                uint16_t tci;

                packet->state = PCAP_THREAD_PACKET_INVALID_IEEE802;
                need16(tci, payload, length);
                packet->ieee802hdr.pcp = (tci & 0xe000) >> 13;
                packet->ieee802hdr.dei = (tci & 0x1000) >> 12;
                packet->ieee802hdr.vid = tci & 0x0fff;
                need16(packet->ieee802hdr.ether_type, payload, length);
                packet->state           = PCAP_THREAD_PACKET_OK;
                packet->have_ieee802hdr = 1;
            }

            if (pcaplist->pcap_thread->callback_ieee802)
                pcaplist->pcap_thread->callback_ieee802(pcaplist->user, packet, payload, length);
            else
                pcap_thread_callback_ieee802((void*)pcaplist, packet, payload, length);
            return;

        case ETHERTYPE_IP:
        case ETHERTYPE_IPV6:
            if (pcaplist->pcap_thread->callback_ip)
                pcaplist->pcap_thread->callback_ip(pcaplist->user, packet, payload, length);
            else
                pcap_thread_callback_ip((void*)pcaplist, packet, payload, length);
            return;

        default:
            packet->state = PCAP_THREAD_PACKET_UNSUPPORTED;
            break;
        }
    }

    if (pcaplist->pcap_thread->callback_invalid) {
        if (packet->state == PCAP_THREAD_PACKET_OK)
            packet->state = PCAP_THREAD_PACKET_INVALID;
        pcaplist->pcap_thread->callback_invalid(pcaplist->user, packet, orig, origlength);
    }
}

static void pcap_thread_callback_null(u_char* user, pcap_thread_packet_t* packet, const u_char* payload, size_t length)
{
    pcap_thread_pcaplist_t* pcaplist   = (pcap_thread_pcaplist_t*)user;
    const u_char*           orig       = payload;
    size_t                  origlength = length;

    if (!pcaplist) {
        return;
    }
    if (!pcaplist->pcap_thread) {
        return;
    }
    if (!packet) {
        return;
    }
    if (!payload) {
        return;
    }
    if (!length) {
        return;
    }

    if (packet->have_nullhdr) {
        layer_trace("have_nullhdr");

        /* From libpcap link types documentation:
         *  containing a value of 2 for IPv4 packets, a value of either 24, 28,
         *  or 30 for IPv6 packets, a value of 7 for OSI packets, or a value of 23
         *  for IPX packets. All of the IPv6 values correspond to IPv6 packets;
         *  code reading files should check for all of them.
         */

        switch (packet->nullhdr.family) {
        case 2:
        case 24:
        case 28:
        case 30:
            if (pcaplist->pcap_thread->callback_ip)
                pcaplist->pcap_thread->callback_ip(pcaplist->user, packet, payload, length);
            else
                pcap_thread_callback_ip((void*)pcaplist, packet, payload, length);
            return;

        default:
            packet->state = PCAP_THREAD_PACKET_UNSUPPORTED;
            break;
        }
    }

    if (pcaplist->pcap_thread->callback_invalid) {
        if (packet->state == PCAP_THREAD_PACKET_OK)
            packet->state = PCAP_THREAD_PACKET_INVALID;
        pcaplist->pcap_thread->callback_invalid(pcaplist->user, packet, orig, origlength);
    }
}

static void pcap_thread_callback_loop(u_char* user, pcap_thread_packet_t* packet, const u_char* payload, size_t length)
{
    pcap_thread_pcaplist_t* pcaplist   = (pcap_thread_pcaplist_t*)user;
    const u_char*           orig       = payload;
    size_t                  origlength = length;

    if (!pcaplist) {
        return;
    }
    if (!pcaplist->pcap_thread) {
        return;
    }
    if (!packet) {
        return;
    }
    if (!payload) {
        return;
    }
    if (!length) {
        return;
    }

    if (packet->have_loophdr) {
        layer_trace("have_loophdr");

        /* From libpcap link types documentation:
         *  containing a value of 2 for IPv4 packets, a value of either 24, 28,
         *  or 30 for IPv6 packets, a value of 7 for OSI packets, or a value of 23
         *  for IPX packets. All of the IPv6 values correspond to IPv6 packets;
         *  code reading files should check for all of them.
         */

        switch (packet->loophdr.family) {
        case 2:
        case 24:
        case 28:
        case 30:
            if (pcaplist->pcap_thread->callback_ip)
                pcaplist->pcap_thread->callback_ip(pcaplist->user, packet, payload, length);
            else
                pcap_thread_callback_ip((void*)pcaplist, packet, payload, length);
            return;

        default:
            packet->state = PCAP_THREAD_PACKET_UNSUPPORTED;
            break;
        }
    }

    if (pcaplist->pcap_thread->callback_invalid) {
        if (packet->state == PCAP_THREAD_PACKET_OK)
            packet->state = PCAP_THREAD_PACKET_INVALID;
        pcaplist->pcap_thread->callback_invalid(pcaplist->user, packet, orig, origlength);
    }
}

static void pcap_thread_callback_ieee802(u_char* user, pcap_thread_packet_t* packet, const u_char* payload, size_t length)
{
    pcap_thread_pcaplist_t* pcaplist   = (pcap_thread_pcaplist_t*)user;
    const u_char*           orig       = payload;
    size_t                  origlength = length;

    if (!pcaplist) {
        return;
    }
    if (!pcaplist->pcap_thread) {
        return;
    }
    if (!packet) {
        return;
    }
    if (!payload) {
        return;
    }
    if (!length) {
        return;
    }

    if (packet->have_ieee802hdr) {
        layer_trace("have_ieee802hdr");

        switch (packet->ieee802hdr.ether_type) {
        case 0x88a8: /* 802.1ad */
        case 0x9100: /* 802.1 QinQ non-standard */
        {
            pcap_thread_packet_t ieee802pkt;
            uint16_t             tci;

            memset(&ieee802pkt, 0, sizeof(ieee802pkt));
            ieee802pkt.prevpkt      = packet;
            ieee802pkt.have_prevpkt = 1;

            packet->state = PCAP_THREAD_PACKET_INVALID_IEEE802;
            need16(tci, payload, length);
            ieee802pkt.ieee802hdr.pcp = (tci & 0xe000) >> 13;
            ieee802pkt.ieee802hdr.dei = (tci & 0x1000) >> 12;
            ieee802pkt.ieee802hdr.vid = tci & 0x0fff;
            need16(ieee802pkt.ieee802hdr.ether_type, payload, length);
            packet->state              = PCAP_THREAD_PACKET_OK;
            ieee802pkt.have_ieee802hdr = 1;

            if (pcaplist->pcap_thread->callback_ieee802)
                pcaplist->pcap_thread->callback_ieee802(pcaplist->user, &ieee802pkt, payload, length);
            else
                pcap_thread_callback_ieee802((void*)pcaplist, &ieee802pkt, payload, length);
            return;
        }

        case ETHERTYPE_IP:
        case ETHERTYPE_IPV6:
            if (pcaplist->pcap_thread->callback_ip)
                pcaplist->pcap_thread->callback_ip(pcaplist->user, packet, payload, length);
            else
                pcap_thread_callback_ip((void*)pcaplist, packet, payload, length);
            return;

        default:
            packet->state = PCAP_THREAD_PACKET_UNSUPPORTED;
            break;
        }
    }

    if (pcaplist->pcap_thread->callback_invalid) {
        if (packet->state == PCAP_THREAD_PACKET_OK)
            packet->state = PCAP_THREAD_PACKET_INVALID;
        pcaplist->pcap_thread->callback_invalid(pcaplist->user, packet, orig, origlength);
    }
}

static void pcap_thread_callback_gre(u_char* user, pcap_thread_packet_t* packet, const u_char* payload, size_t length)
{
    pcap_thread_pcaplist_t* pcaplist   = (pcap_thread_pcaplist_t*)user;
    const u_char*           orig       = payload;
    size_t                  origlength = length;

    if (!pcaplist) {
        return;
    }
    if (!pcaplist->pcap_thread) {
        return;
    }
    if (!packet) {
        return;
    }
    if (!payload) {
        return;
    }
    if (!length) {
        return;
    }

    if (packet->have_grehdr) {
        pcap_thread_packet_t grepkt;

        layer_trace("have_grehdr");

        memset(&grepkt, 0, sizeof(grepkt));
        grepkt.prevpkt      = packet;
        grepkt.have_prevpkt = 1;

        for (;;) {
            packet->state = PCAP_THREAD_PACKET_INVALID_GRE;
            if (packet->grehdr.gre_flags & 0x1) {
                need16(packet->gre.checksum, payload, length);
            }
            if (packet->grehdr.gre_flags & 0x4) {
                need16(packet->gre.key, payload, length);
            }
            if (packet->grehdr.gre_flags & 0x8) {
                need16(packet->gre.sequence, payload, length);
            }
            packet->state    = PCAP_THREAD_PACKET_OK;
            packet->have_gre = 1;

            switch (packet->grehdr.ether_type) {
            case ETHERTYPE_IP:
            case ETHERTYPE_IPV6:
                if (pcaplist->pcap_thread->callback_ip)
                    pcaplist->pcap_thread->callback_ip(pcaplist->user, &grepkt, payload, length);
                else
                    pcap_thread_callback_ip((void*)pcaplist, &grepkt, payload, length);
                return;

            default:
                packet->state = PCAP_THREAD_PACKET_UNSUPPORTED;
                break;
            }
            break;
        }
    }

    if (pcaplist->pcap_thread->callback_invalid) {
        if (packet->state == PCAP_THREAD_PACKET_OK)
            packet->state = PCAP_THREAD_PACKET_INVALID;
        pcaplist->pcap_thread->callback_invalid(pcaplist->user, packet, orig, origlength);
    }
}

static void pcap_thread_callback_ip(u_char* user, pcap_thread_packet_t* packet, const u_char* payload, size_t length)
{
    pcap_thread_pcaplist_t* pcaplist   = (pcap_thread_pcaplist_t*)user;
    const u_char*           orig       = payload;
    size_t                  origlength = length;

    if (!pcaplist) {
        return;
    }
    if (!pcaplist->pcap_thread) {
        return;
    }
    if (!packet) {
        return;
    }
    if (!payload) {
        return;
    }
    if (!length) {
        return;
    }

    if (!packet->have_iphdr && !packet->have_ip6hdr) {
        layer_trace("checking for ip");

        for (;;) {
            packet->state = PCAP_THREAD_PACKET_INVALID_IP;
            need4x2(packet->iphdr.ip_v, packet->iphdr.ip_hl, payload, length);
            if (packet->iphdr.ip_v == 4) {
                packet->state = PCAP_THREAD_PACKET_INVALID_IPV4;
                need8(packet->iphdr.ip_tos, payload, length);
                need16(packet->iphdr.ip_len, payload, length);
                need16(packet->iphdr.ip_id, payload, length);
                need16(packet->iphdr.ip_off, payload, length);
                need8(packet->iphdr.ip_ttl, payload, length);
                need8(packet->iphdr.ip_p, payload, length);
                need16(packet->iphdr.ip_sum, payload, length);
                need32(packet->iphdr.ip_src.s_addr, payload, length);
                need32(packet->iphdr.ip_dst.s_addr, payload, length);

                /* TODO: IPv4 options */

                if (packet->iphdr.ip_hl < 5)
                    break;
                if (packet->iphdr.ip_hl > 5) {
                    advancexb((packet->iphdr.ip_hl - 5) * 4, payload, length);
                }

                packet->state      = PCAP_THREAD_PACKET_OK;
                packet->have_iphdr = 1;

                if (pcaplist->pcap_thread->callback_ipv4)
                    pcaplist->pcap_thread->callback_ipv4(pcaplist->user, packet, payload, length);
                else
                    pcap_thread_callback_ipv4((void*)pcaplist, packet, payload, length);
                return;
            } else if (packet->iphdr.ip_v == 6) {
                /*
                 * Clear IPv4 headers and reverse reading one byte
                 */
                packet->iphdr.ip_v  = 0;
                packet->iphdr.ip_hl = 0;
                payload--;
                length++;

                packet->state = PCAP_THREAD_PACKET_INVALID_IPV6;
                need32(packet->ip6hdr.ip6_flow, payload, length);
                need16(packet->ip6hdr.ip6_plen, payload, length);
                need8(packet->ip6hdr.ip6_nxt, payload, length);
                need8(packet->ip6hdr.ip6_hlim, payload, length);
                needxb(&(packet->ip6hdr.ip6_src), 16, payload, length);
                needxb(&(packet->ip6hdr.ip6_dst), 16, payload, length);
                packet->state       = PCAP_THREAD_PACKET_OK;
                packet->have_ip6hdr = 1;

                if (pcaplist->pcap_thread->callback_ipv6)
                    pcaplist->pcap_thread->callback_ipv6(pcaplist->user, packet, payload, length);
                else
                    pcap_thread_callback_ipv6((void*)pcaplist, packet, payload, length);
                return;
            }

            packet->state = PCAP_THREAD_PACKET_UNSUPPORTED;
            break;
        }
    }

    if (pcaplist->pcap_thread->callback_invalid) {
        if (packet->state == PCAP_THREAD_PACKET_OK)
            packet->state = PCAP_THREAD_PACKET_INVALID;
        pcaplist->pcap_thread->callback_invalid(pcaplist->user, packet, orig, origlength);
    }
}

static void pcap_thread_callback_ipv4(u_char* user, pcap_thread_packet_t* packet, const u_char* payload, size_t length)
{
    pcap_thread_pcaplist_t* pcaplist   = (pcap_thread_pcaplist_t*)user;
    const u_char*           orig       = payload;
    size_t                  origlength = length;

    if (!pcaplist) {
        return;
    }
    if (!pcaplist->pcap_thread) {
        return;
    }
    if (!packet) {
        return;
    }
    if (!payload) {
        return;
    }
    if (!length) {
        return;
    }

    if (packet->have_iphdr) {
        layer_trace("have_iphdr");

        for (;;) {
            if (!(packet->iphdr.ip_off & 0x4000) /* may fragment */
                && !(!(packet->iphdr.ip_off & 0x2000) && !(packet->iphdr.ip_off & 0x1fff))) /* first and last fragment */
            {
                /* The packet may be fragmented and is not the first and last fragment */

                /* TODO: need to reassemble */
                packet->state = PCAP_THREAD_PACKET_UNSUPPORTED;
                break;
            }

            switch (packet->iphdr.ip_p) {
            case IPPROTO_GRE:
                layer_trace("ipproto_gre");

                if (packet->have_grehdr)
                    break;

                packet->state = PCAP_THREAD_PACKET_INVALID_GRE;
                need16(packet->grehdr.gre_flags, payload, length);
                need16(packet->grehdr.ether_type, payload, length);
                packet->state       = PCAP_THREAD_PACKET_OK;
                packet->have_grehdr = 1;

                if (pcaplist->pcap_thread->callback_gre)
                    pcaplist->pcap_thread->callback_gre(pcaplist->user, packet, payload, length);
                else
                    pcap_thread_callback_gre((void*)pcaplist, packet, payload, length);
                return;

            case IPPROTO_UDP:
                layer_trace("ipproto_udp");

                if (packet->have_udphdr)
                    break;

                packet->state = PCAP_THREAD_PACKET_INVALID_UDP;
                need16(packet->udphdr.uh_sport, payload, length);
                need16(packet->udphdr.uh_dport, payload, length);
                need16(packet->udphdr.uh_ulen, payload, length);
                need16(packet->udphdr.uh_sum, payload, length);
                packet->state       = PCAP_THREAD_PACKET_OK;
                packet->have_udphdr = 1;

                if (pcaplist->pcap_thread->callback_udp)
                    pcaplist->pcap_thread->callback_udp(pcaplist->user, packet, payload, length);
                else
                    pcap_thread_callback_udp((void*)pcaplist, packet, payload, length);
                return;

            case IPPROTO_TCP:
                layer_trace("ipproto_tcp");

                if (packet->have_tcphdr)
                    break;

                packet->state = PCAP_THREAD_PACKET_INVALID_TCP;
                need16(packet->tcphdr.th_sport, payload, length);
                need16(packet->tcphdr.th_dport, payload, length);
                need32(packet->tcphdr.th_seq, payload, length);
                need32(packet->tcphdr.th_ack, payload, length);
                need4x2(packet->tcphdr.th_off, packet->tcphdr.th_x2, payload, length);
                need8(packet->tcphdr.th_flags, payload, length);
                need16(packet->tcphdr.th_win, payload, length);
                need16(packet->tcphdr.th_sum, payload, length);
                need16(packet->tcphdr.th_urp, payload, length);
                packet->state       = PCAP_THREAD_PACKET_OK;
                packet->have_tcphdr = 1;

                if (pcaplist->pcap_thread->callback_tcp)
                    pcaplist->pcap_thread->callback_tcp(pcaplist->user, packet, payload, length);
                else
                    pcap_thread_callback_tcp((void*)pcaplist, packet, payload, length);
                return;

            default:
                packet->state = PCAP_THREAD_PACKET_UNSUPPORTED;
                break;
            }
            break;
        }
    }

    if (pcaplist->pcap_thread->callback_invalid) {
        if (packet->state == PCAP_THREAD_PACKET_OK)
            packet->state = PCAP_THREAD_PACKET_INVALID;
        pcaplist->pcap_thread->callback_invalid(pcaplist->user, packet, orig, origlength);
    }
}

static void pcap_thread_callback_ipv6(u_char* user, pcap_thread_packet_t* packet, const u_char* payload, size_t length)
{
    pcap_thread_pcaplist_t* pcaplist   = (pcap_thread_pcaplist_t*)user;
    const u_char*           orig       = payload;
    size_t                  origlength = length;

    if (!pcaplist) {
        return;
    }
    if (!pcaplist->pcap_thread) {
        return;
    }
    if (!packet) {
        return;
    }
    if (!payload) {
        return;
    }
    if (!length) {
        return;
    }

    if (packet->have_ip6hdr) {
        struct ip6_ext ext;

        layer_trace("have_ip6hdr");

        ext.ip6e_nxt = packet->ip6hdr.ip6_nxt;
        ext.ip6e_len = 0;

        while (ext.ip6e_nxt != IPPROTO_NONE
               && ext.ip6e_nxt != IPPROTO_GRE
               && ext.ip6e_nxt != IPPROTO_UDP
               && ext.ip6e_nxt != IPPROTO_TCP) {
            packet->state = PCAP_THREAD_PACKET_INVALID_IPV6HDR;
            if (ext.ip6e_len) {
                advancexb((ext.ip6e_len * 8), payload, length);
            }

            need8(ext.ip6e_nxt, payload, length);
            need8(ext.ip6e_len, payload, length);
            packet->state = PCAP_THREAD_PACKET_OK;

            /* TODO: Store IPv6 headers? */
            /* TODO: Handle IPPROTO_FRAGMENT */

            if (!ext.ip6e_len)
                break;
        }

        switch (ext.ip6e_nxt) {
        case IPPROTO_GRE:
            if (packet->have_grehdr)
                break;

            packet->state = PCAP_THREAD_PACKET_INVALID_GRE;
            need16(packet->grehdr.gre_flags, payload, length);
            need16(packet->grehdr.ether_type, payload, length);
            packet->state       = PCAP_THREAD_PACKET_OK;
            packet->have_grehdr = 1;

            if (pcaplist->pcap_thread->callback_gre)
                pcaplist->pcap_thread->callback_gre(pcaplist->user, packet, payload, length);
            else
                pcap_thread_callback_gre((void*)pcaplist, packet, payload, length);
            return;

        case IPPROTO_UDP:
            if (packet->have_udphdr)
                break;

            packet->state = PCAP_THREAD_PACKET_INVALID_UDP;
            need16(packet->udphdr.uh_sport, payload, length);
            need16(packet->udphdr.uh_dport, payload, length);
            need16(packet->udphdr.uh_ulen, payload, length);
            need16(packet->udphdr.uh_sum, payload, length);
            packet->state       = PCAP_THREAD_PACKET_OK;
            packet->have_udphdr = 1;

            if (pcaplist->pcap_thread->callback_udp)
                pcaplist->pcap_thread->callback_udp(pcaplist->user, packet, payload, length);
            else
                pcap_thread_callback_udp((void*)pcaplist, packet, payload, length);
            return;

        case IPPROTO_TCP:
            if (packet->have_tcphdr)
                break;

            packet->state = PCAP_THREAD_PACKET_INVALID_TCP;
            need16(packet->tcphdr.th_sport, payload, length);
            need16(packet->tcphdr.th_dport, payload, length);
            need32(packet->tcphdr.th_seq, payload, length);
            need32(packet->tcphdr.th_ack, payload, length);
            need4x2(packet->tcphdr.th_off, packet->tcphdr.th_x2, payload, length);
            need8(packet->tcphdr.th_flags, payload, length);
            need16(packet->tcphdr.th_win, payload, length);
            need16(packet->tcphdr.th_sum, payload, length);
            need16(packet->tcphdr.th_urp, payload, length);
            packet->state       = PCAP_THREAD_PACKET_OK;
            packet->have_tcphdr = 1;

            if (pcaplist->pcap_thread->callback_tcp)
                pcaplist->pcap_thread->callback_tcp(pcaplist->user, packet, payload, length);
            else
                pcap_thread_callback_tcp((void*)pcaplist, packet, payload, length);
            return;

        default:
            packet->state = PCAP_THREAD_PACKET_UNSUPPORTED;
            break;
        }
    }

    if (pcaplist->pcap_thread->callback_invalid) {
        if (packet->state == PCAP_THREAD_PACKET_OK)
            packet->state = PCAP_THREAD_PACKET_INVALID;
        pcaplist->pcap_thread->callback_invalid(pcaplist->user, packet, orig, origlength);
    }
}

static void pcap_thread_callback_udp(u_char* user, pcap_thread_packet_t* packet, const u_char* payload, size_t length)
{
    pcap_thread_pcaplist_t* pcaplist   = (pcap_thread_pcaplist_t*)user;
    const u_char*           orig       = payload;
    size_t                  origlength = length;

    if (!pcaplist) {
        return;
    }
    if (!pcaplist->pcap_thread) {
        return;
    }
    if (!packet) {
        return;
    }
    if (!payload) {
        return;
    }
    if (!length) {
        return;
    }

    /* TODO: Higher layer support? */
    packet->state = PCAP_THREAD_PACKET_UNPROCESSED;

    if (pcaplist->pcap_thread->callback_invalid) {
        if (packet->state == PCAP_THREAD_PACKET_OK)
            packet->state = PCAP_THREAD_PACKET_INVALID;
        pcaplist->pcap_thread->callback_invalid(pcaplist->user, packet, orig, origlength);
    }
}

static void pcap_thread_callback_tcp(u_char* user, pcap_thread_packet_t* packet, const u_char* payload, size_t length)
{
    pcap_thread_pcaplist_t* pcaplist   = (pcap_thread_pcaplist_t*)user;
    const u_char*           orig       = payload;
    size_t                  origlength = length;

    if (!pcaplist) {
        return;
    }
    if (!pcaplist->pcap_thread) {
        return;
    }
    if (!packet) {
        return;
    }
    if (!payload) {
        return;
    }
    if (!length) {
        return;
    }

    /* TODO: Higher layer support? */
    packet->state = PCAP_THREAD_PACKET_UNPROCESSED;

    if (pcaplist->pcap_thread->callback_invalid) {
        if (packet->state == PCAP_THREAD_PACKET_OK)
            packet->state = PCAP_THREAD_PACKET_INVALID;
        pcaplist->pcap_thread->callback_invalid(pcaplist->user, packet, orig, origlength);
    }
}

/*
 * Open/Close
 */

static pcap_thread_pcaplist_t _pcaplist_defaults = PCAP_THREAD_PCAPLIST_T_INIT;

int pcap_thread_open(pcap_thread_t* pcap_thread, const char* device, void* user)
{
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
    if (pcap_thread->have_timestamp_type && (pcap_thread->status = pcap_set_tstamp_type(pcap, pcap_thread->timestamp_type))) {
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
            pcaplist->have_bpf        = 1;
            pcap_thread->filter_errno = 0;
            errno                     = 0;
            if ((pcap_thread->status = pcap_setfilter(pcap, &(pcaplist->bpf)))) {
                pcap_freecode(&(pcaplist->bpf));
                pcap_close(pcap);
                free(pcaplist->name);
                free(pcaplist);
                PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_setfilter()");
                return PCAP_THREAD_EPCAP;
            }
            pcap_thread->filter_errno = errno;
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

int pcap_thread_open_offline(pcap_thread_t* pcap_thread, const char* file, void* user)
{
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
    } else
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
        pcaplist->have_bpf        = 1;
        pcap_thread->filter_errno = 0;
        errno                     = 0;
        if ((pcap_thread->status = pcap_setfilter(pcap, &(pcaplist->bpf)))) {
            pcap_freecode(&(pcaplist->bpf));
            pcap_close(pcap);
            free(pcaplist->name);
            free(pcaplist);
            PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_setfilter()");
            return PCAP_THREAD_EPCAP;
        }
        pcap_thread->filter_errno = errno;
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

int pcap_thread_add(pcap_thread_t* pcap_thread, const char* name, pcap_t* pcap, void* user)
{
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

int pcap_thread_activate(pcap_thread_t* pcap_thread)
{
    pcap_thread_pcaplist_t* pcaplist;
    int                     snapshot;

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

    pcap_thread->filter_errno = 0;
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
            errno              = 0;
            if ((pcap_thread->status = pcap_setfilter(pcaplist->pcap, &(pcaplist->bpf)))) {
                PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_setfilter()");
                return PCAP_THREAD_EPCAP;
            }
            if (errno && !pcap_thread->filter_errno)
                pcap_thread->filter_errno = errno;
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

int pcap_thread_close(pcap_thread_t* pcap_thread)
{
    pcap_thread_pcaplist_t* pcaplist;

    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (pcap_thread->running) {
        return PCAP_THREAD_ERUNNING;
    }

    while (pcap_thread->pcaplist) {
        pcaplist              = pcap_thread->pcaplist;
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
    pcap_thread->step = 0;

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

    return PCAP_THREAD_OK;
}

/*
 * Engine
 */

#ifdef HAVE_PTHREAD
static void _callback(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* pkt)
{
    pcap_thread_pcaplist_t* pcaplist;
    pcap_thread_t*          pcap_thread;

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

    if (pcap_thread->queue_mode == PCAP_THREAD_QUEUE_MODE_DIRECT) {
        if (pcap_thread->callback) {
            pcap_thread->callback(pcaplist->user, pkthdr, pkt, pcaplist->name, pcap_datalink(pcaplist->pcap));
        } else if (pcaplist->layer_callback) {
            pcaplist->layer_callback((void*)pcaplist, pkthdr, pkt, pcaplist->name, pcap_datalink(pcaplist->pcap));
        } else if (pcap_thread->dropback) {
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

static void* _thread(void* vp)
{
    pcap_thread_pcaplist_t* pcaplist;
    int                     ret = 0;

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

static void _callback2(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* pkt)
{
    pcap_thread_pcaplist_t* pcaplist;

    if (!user) {
        return;
    }
    pcaplist = (pcap_thread_pcaplist_t*)user;

    if (!pcaplist->pcap_thread) {
        pcaplist->running = 0;
        return;
    }
    if (pcaplist->pcap_thread->callback) {
        pcaplist->pcap_thread->callback(pcaplist->user, pkthdr, pkt, pcaplist->name, pcap_datalink(pcaplist->pcap));
    } else if (pcaplist->layer_callback) {
        pcaplist->layer_callback((void*)pcaplist, pkthdr, pkt, pcaplist->name, pcap_datalink(pcaplist->pcap));
    } else {
        pcaplist->running = 0;
    }
}

int pcap_thread_run(pcap_thread_t* pcap_thread)
{
    pcap_thread_pcaplist_t* pcaplist;
    int                     run = 1, timedrun = 0;
    struct timeval          start = { 0, 0 };
    struct timespec         end   = { 0, 0 };

    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (!pcap_thread->pcaplist) {
        return PCAP_THREAD_NOPCAPS;
    }
    if (!pcap_thread->callback && !pcap_thread->use_layers) {
        return PCAP_THREAD_NOCALLBACK;
    }
    if (pcap_thread->use_layers
        && !(pcap_thread->callback_linux_sll
               || pcap_thread->callback_ether
               || pcap_thread->callback_null
               || pcap_thread->callback_loop
               || pcap_thread->callback_ieee802
               || pcap_thread->callback_gre
               || pcap_thread->callback_ip
               || pcap_thread->callback_ipv4
               || pcap_thread->callback_ipv6
               || pcap_thread->callback_udp
               || pcap_thread->callback_tcp)) {
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
                     + ((start.tv_usec + pcap_thread->timedrun.tv_usec) / 1000000);
        end.tv_nsec = ((start.tv_usec + pcap_thread->timedrun.tv_usec) % 1000000) * 1000;
    } else if (pcap_thread->timedrun_to.tv_sec) {
        timedrun = 1;

        end.tv_sec  = pcap_thread->timedrun_to.tv_sec;
        end.tv_nsec = pcap_thread->timedrun_to.tv_usec * 1000;
    }

#ifdef HAVE_PTHREAD
    if (pcap_thread->use_threads) {
        int err, all_offline;

        switch (pcap_thread->queue_mode) {
        case PCAP_THREAD_QUEUE_MODE_COND:
        case PCAP_THREAD_QUEUE_MODE_DIRECT:
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

        pcap_thread->read_pos  = 0;
        pcap_thread->write_pos = 0;
        pcap_thread->pkts      = 0;

        all_offline = 1;
        for (pcaplist = pcap_thread->pcaplist; all_offline && pcaplist; pcaplist = pcaplist->next) {
            if (!pcaplist->is_offline) {
                all_offline = 0;
                break;
            }
        }

        pcap_thread->running     = 1;
        pcap_thread->was_stopped = 0;
        err                      = PCAP_THREAD_OK;

        for (pcaplist = pcap_thread->pcaplist; pcaplist; pcaplist = pcaplist->next) {
            pcaplist->pcap_thread = pcap_thread;
            if (pcap_thread->use_layers) {
                pcaplist->layer_callback = &pcap_thread_callback;
            }
            pcaplist->running = 1;

            if ((err = pthread_create(&(pcaplist->thread), 0, _thread, (void*)pcaplist))) {
                errno = err;
                err   = PCAP_THREAD_ERRNO;
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

                if (pcap_thread->callback) {
                    pcap_thread->callback(
                        pcap_thread->pcaplist_pkt[pcap_thread->read_pos]->user,
                        &(pcap_thread->pkthdr[pcap_thread->read_pos]),
                        &(pcap_thread->pkt[pcap_thread->read_pos * pcap_thread->snapshot]),
                        pcap_thread->pcaplist_pkt[pcap_thread->read_pos]->name,
                        pcap_datalink(pcap_thread->pcaplist_pkt[pcap_thread->read_pos]->pcap));
                } else {
                    pcap_thread_callback(
                        (void*)pcap_thread->pcaplist_pkt[pcap_thread->read_pos],
                        &(pcap_thread->pkthdr[pcap_thread->read_pos]),
                        &(pcap_thread->pkt[pcap_thread->read_pos * pcap_thread->snapshot]),
                        pcap_thread->pcaplist_pkt[pcap_thread->read_pos]->name,
                        pcap_datalink(pcap_thread->pcaplist_pkt[pcap_thread->read_pos]->pcap));
                }

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
                err   = PCAP_THREAD_ERRNO;
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
                    || (now.tv_sec == end.tv_sec && (now.tv_usec * 1000) >= end.tv_nsec)) {
                    break;
                }

                err = pthread_cond_timedwait(&(pcap_thread->have_packets), &(pcap_thread->mutex), &end);
                if (err == ETIMEDOUT) {
                    err = PCAP_THREAD_OK;
                } else if (err) {
                    errno = err;
                    err   = PCAP_THREAD_ERRNO;
                    PCAP_THREAD_SET_ERRBUF(pcap_thread, "pthread_cond_timedwait()");
                    break;
                }
            } else {
                if ((err = pthread_cond_wait(&(pcap_thread->have_packets), &(pcap_thread->mutex)))) {
                    errno = err;
                    err   = PCAP_THREAD_ERRNO;
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
    } else
#endif
    {
        fd_set         fds, rfds;
        int            max_fd = 0;
        struct timeval t1, t2;

        pcap_thread->running     = 1;
        pcap_thread->was_stopped = 0;

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
            pcaplist->running     = 1;
        }

        t1.tv_sec  = pcap_thread->timeout / 1000;
        t1.tv_usec = (pcap_thread->timeout % 1000) * 1000;
        max_fd++;
        while (run) {
            rfds = fds;
            t2   = t1;
            if (timedrun) {
                struct timeval now;
                struct timeval diff;

                if (gettimeofday(&now, 0)) {
                    PCAP_THREAD_SET_ERRBUF(pcap_thread, "gettimeofday()");
                    pcap_thread->running = 0;
                    return PCAP_THREAD_ERRNO;
                }
                if (now.tv_sec > end.tv_sec
                    || (now.tv_sec == end.tv_sec && (now.tv_usec * 1000) >= end.tv_nsec)) {
                    break;
                }

                if (end.tv_sec > now.tv_sec) {
                    diff.tv_sec  = end.tv_sec - now.tv_sec - 1;
                    diff.tv_usec = 1000000 - now.tv_usec;
                    diff.tv_usec += end.tv_nsec / 1000;
                    if (diff.tv_usec > 1000000) {
                        diff.tv_sec += diff.tv_usec / 1000000;
                        diff.tv_usec %= 1000000;
                    }
                } else {
                    diff.tv_sec = 0;
                    if (end.tv_sec == now.tv_sec && (end.tv_nsec / 1000) > now.tv_usec) {
                        diff.tv_usec = (end.tv_nsec / 1000) - now.tv_usec;
                    } else {
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
                } else {
                    run = 1;
                }

                packets = pcap_dispatch(pcaplist->pcap, -1, _callback2, (u_char*)pcaplist);
                if (packets == -1) {
                    pcap_thread->status = -1;
                    PCAP_THREAD_SET_ERRBUF(pcap_thread, "pcap_dispatch()");
                    pcap_thread->running = 0;
                    return PCAP_THREAD_EPCAP;
                } else if (packets == -2 || (pcaplist->is_offline && !packets)) {
                    pcaplist->running = 0;
                }
            }
        }

        pcap_thread->running = 0;
    }

    return PCAP_THREAD_OK;
}

int pcap_thread_next(pcap_thread_t* pcap_thread)
{
    const u_char*      pkt;
    struct pcap_pkthdr pkthdr;

    if (!pcap_thread) {
        return PCAP_THREAD_EINVAL;
    }
    if (!pcap_thread->callback && !pcap_thread->use_layers) {
        return PCAP_THREAD_NOCALLBACK;
    }
    if (pcap_thread->use_layers
        && !(pcap_thread->callback_linux_sll
               || pcap_thread->callback_ether
               || pcap_thread->callback_null
               || pcap_thread->callback_loop
               || pcap_thread->callback_ieee802
               || pcap_thread->callback_gre
               || pcap_thread->callback_ip
               || pcap_thread->callback_ipv4
               || pcap_thread->callback_ipv6
               || pcap_thread->callback_udp
               || pcap_thread->callback_tcp)) {
        return PCAP_THREAD_NOCALLBACK;
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
    if (pcap_thread->callback) {
        pcap_thread->callback(pcap_thread->step->user, &pkthdr, pkt, pcap_thread->step->name, pcap_datalink(pcap_thread->step->pcap));
    } else {
        pcap_thread_callback((void*)pcap_thread->step, &pkthdr, pkt, pcap_thread->step->name, pcap_datalink(pcap_thread->step->pcap));
    }
    pcap_thread->step = pcap_thread->step->next;

    return PCAP_THREAD_OK;
}

int pcap_thread_next_reset(pcap_thread_t* pcap_thread)
{
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

int pcap_thread_stop(pcap_thread_t* pcap_thread)
{
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
    pcap_thread->running     = 0;
    pcap_thread->was_stopped = 1;

#ifdef HAVE_PTHREAD
    pthread_cond_broadcast(&(pcap_thread->have_packets));
    pthread_cond_broadcast(&(pcap_thread->can_write));
#endif

    return PCAP_THREAD_OK;
}

/*
 * Stats
 */

int pcap_thread_stats(pcap_thread_t* pcap_thread, pcap_thread_stats_callback_t callback, u_char* user)
{
    pcap_thread_pcaplist_t* pcaplist;
    struct pcap_stat        stats;

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
        if (pcaplist->is_offline)
            continue;
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

int pcap_thread_status(const pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        return 0;
    }

    return pcap_thread->status;
}

const char* pcap_thread_errbuf(const pcap_thread_t* pcap_thread)
{
    if (!pcap_thread) {
        return 0;
    }

    return pcap_thread->errbuf;
}

const char* pcap_thread_strerr(int error)
{
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
    case PCAP_THREAD_ELAYERCB:
        return PCAP_THREAD_ELAYERCB_STR;
    }
    return "UNKNOWN";
}
