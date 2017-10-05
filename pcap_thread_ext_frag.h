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

#include "pcap_thread.h"

#ifndef __pcap_thread_ext_frag_h
#define __pcap_thread_ext_frag_h

#ifdef __cplusplus
extern "C" {
#endif

/*
 * RFC791 - Handle fragments in an offset ascending order, allow fragments to overlap
 * RFC815 - Handle fragments in a receiving order, allow fragments to overlap
 * BSD    - Handle fragments in an offset descending order, allow fragments to overlap
 */
typedef enum pcap_thread_ext_frag_reassemble_mode pcap_thread_ext_frag_reassemble_mode_t;
enum pcap_thread_ext_frag_reassemble_mode {
    PCAP_THREAD_EXT_FRAG_REASSEMBLE_RFC791 = 0,
    PCAP_THREAD_EXT_FRAG_REASSEMBLE_RFC815,
    PCAP_THREAD_EXT_FRAG_REASSEMBLE_BSD
};

typedef struct pcap_thread_ext_frag_fragment pcap_thread_ext_frag_fragment_t;
struct pcap_thread_ext_frag_fragment {
    pcap_thread_ext_frag_fragment_t* next;

    unsigned short flag_more_fragments : 1;

    u_char* payload;
    size_t  length;
    size_t  offset;
};

typedef struct pcap_thread_ext_frag_fragments pcap_thread_ext_frag_fragments_t;
struct pcap_thread_ext_frag_fragments {
    pcap_thread_ext_frag_fragments_t* next;

    pcap_thread_packet_t             packet;
    pcap_thread_ext_frag_fragment_t* fragments;
    size_t                           num_fragments;
    u_char*                          payload;
    size_t                           length;
};

typedef void (*pcap_thread_ext_frag_callback_t)(const pcap_thread_packet_t* packet, const u_char* payload, size_t length, const pcap_thread_ext_frag_fragments_t* fragments);

/* clang-format off */
#define PCAP_THREAD_EXT_FRAG_CONF_T_INIT { \
    0, 0, \
    PCAP_THREAD_EXT_FRAG_REASSEMBLE_RFC791, \
    100, 10, { 30, 0 }, \
    0, 0 \
}
/* clang-format on */

typedef struct pcap_thread_ext_frag_conf pcap_thread_ext_frag_conf_t;
struct pcap_thread_ext_frag_conf {
    unsigned short reject_overlap : 1;
    unsigned short check_timeout : 1;

    pcap_thread_ext_frag_reassemble_mode_t reassemble_mode;

    size_t         fragments;
    size_t         per_packet;
    struct timeval timeout;

    pcap_thread_ext_frag_callback_t overlap_callback;
    pcap_thread_ext_frag_callback_t timeout_callback;
};

pcap_thread_ext_frag_conf_t* pcap_thread_ext_frag_conf_new(void);
void pcap_thread_ext_frag_conf_free(pcap_thread_ext_frag_conf_t* conf);

int pcap_thread_ext_frag_conf_reject_overlap(const pcap_thread_ext_frag_conf_t* conf);
int pcap_thread_ext_frag_conf_set_reject_overlap(pcap_thread_ext_frag_conf_t* conf, const int reject_overlap);
int pcap_thread_ext_frag_conf_check_timeout(const pcap_thread_ext_frag_conf_t* conf);
int pcap_thread_ext_frag_conf_set_check_timeout(pcap_thread_ext_frag_conf_t* conf, const int check_timeout);
pcap_thread_ext_frag_reassemble_mode_t pcap_thread_ext_frag_conf_reassemble_mode(const pcap_thread_ext_frag_conf_t* conf);
int pcap_thread_ext_frag_conf_set_reassemble_mode(pcap_thread_ext_frag_conf_t* conf, const pcap_thread_ext_frag_reassemble_mode_t reassemble_mode);
size_t pcap_thread_ext_frag_conf_fragments(const pcap_thread_ext_frag_conf_t* conf);
int pcap_thread_ext_frag_conf_set_fragments(pcap_thread_ext_frag_conf_t* conf, const size_t fragments);
size_t pcap_thread_ext_frag_conf_per_packet(const pcap_thread_ext_frag_conf_t* conf);
int pcap_thread_ext_frag_conf_set_per_packet(pcap_thread_ext_frag_conf_t* conf, const size_t per_packet);
struct timeval pcap_thread_ext_frag_conf_timeout(const pcap_thread_ext_frag_conf_t* conf);
int pcap_thread_ext_frag_conf_set_timeout(pcap_thread_ext_frag_conf_t* conf, const struct timeval timeout);
pcap_thread_ext_frag_callback_t pcap_thread_ext_frag_conf_overlap_callback(const pcap_thread_ext_frag_conf_t* conf);
int pcap_thread_ext_frag_conf_set_overlap_callback(pcap_thread_ext_frag_conf_t* conf, pcap_thread_ext_frag_callback_t overlap_callback);
pcap_thread_ext_frag_callback_t pcap_thread_ext_frag_conf_timeout_callback(const pcap_thread_ext_frag_conf_t* conf);
int pcap_thread_ext_frag_conf_set_timeout_callback(pcap_thread_ext_frag_conf_t* conf, pcap_thread_ext_frag_callback_t timeout_callback);

pcap_thread_layer_callback_frag_t pcap_thread_ext_frag_layer_callback(pcap_thread_ext_frag_conf_t* conf);

#ifdef __cplusplus
}
#endif

#endif /* __pcap_thread_ext_frag_h */
