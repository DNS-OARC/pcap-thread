/*
 * Author Jerry Lundström <jerry@dns-oarc.net>
 * Copyright (c) 2016-2023, OARC, Inc.
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
#include <sys/socket.h>
#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#else
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#ifdef HAVE_MACHINE_ENDIAN_H
#include <machine/endian.h>
#endif

#ifndef __BYTE_ORDER
#if defined(BYTE_ORDER)
#define __BYTE_ORDER BYTE_ORDER
#elif defined(_BYTE_ORDER)
#define __BYTE_ORDER _BYTE_ORDER
#else
#error "No endian byte order define, please fix"
#endif
#endif
#ifndef __LITTLE_ENDIAN
#if defined(LITTLE_ENDIAN)
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#elif defined(_LITTLE_ENDIAN)
#define __LITTLE_ENDIAN _LITTLE_ENDIAN
#else
#error "No little endian define, please fix"
#endif
#endif
#ifndef __BIG_ENDIAN
#if defined(BIG_ENDIAN)
#define __BIG_ENDIAN BIG_ENDIAN
#elif defined(_BIG_ENDIAN)
#define __BIG_ENDIAN _BIG_ENDIAN
#else
#error "No big endian define, please fix"
#endif
#endif

#ifndef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN 0xffffffff
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* clang-format off */

#define PCAP_THREAD_VERSION_STR     "4.0.1"
#define PCAP_THREAD_VERSION_MAJOR   4
#define PCAP_THREAD_VERSION_MINOR   0
#define PCAP_THREAD_VERSION_PATCH   1

#define PCAP_THREAD_DEFAULT_TIMEOUT       1000
#define PCAP_THREAD_DEFAULT_QUEUE_SIZE    64
#define PCAP_THREAD_DEFAULT_QUEUE_MODE    PCAP_THREAD_QUEUE_MODE_COND
#define PCAP_THREAD_DEFAULT_ACTIVATE_MODE PCAP_THREAD_ACTIVATE_MODE_IMMEDIATE

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
#define PCAP_THREAD_EOBSOLETE       11
#define PCAP_THREAD_ERUNNING        12
#define PCAP_THREAD_ENOPCAPLIST     13
#define PCAP_THREAD_ELAYERCB        14

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
#define PCAP_THREAD_EOBSOLETE_STR   "obsolete function or feature"
#define PCAP_THREAD_ERUNNING_STR    "pcap thread are running, can not complete task"
#define PCAP_THREAD_ENOPCAPLIST_STR "no internal reference to the pcap that captured the packet"
#define PCAP_THREAD_ELAYERCB_STR    "layer callback already set in lower or higher segment"

/* clang-format on */

struct pcap_thread_linux_sll {
    uint16_t packet_type;
    uint16_t arp_hardware;
    uint16_t link_layer_address_length;
    uint8_t  link_layer_address[8];
    uint16_t ether_type;
};
struct pcap_thread_linux_sll2 {
    uint16_t protocol_type;
    uint16_t reserved;
    uint32_t interface_index;
    uint16_t arphrd_type;
    uint8_t  packet_type;
    uint8_t  link_layer_address_length;
    uint8_t  link_layer_address[8];
};
struct pcap_thread_null_hdr {
    uint32_t family;
};
struct pcap_thread_loop_hdr {
    uint32_t family;
};
struct pcap_thread_ieee802_hdr {
    uint16_t       tpid;
    unsigned short pcp : 3;
    unsigned short dei : 1;
    unsigned short vid : 12;
    uint16_t       ether_type;
};
struct pcap_thread_gre_hdr {
    uint16_t gre_flags;
    uint16_t ether_type;
};
struct pcap_thread_gre {
    uint16_t checksum;
    uint16_t key;
    uint16_t sequence;
};
typedef enum pcap_thread_packet_state pcap_thread_packet_state_t;
enum pcap_thread_packet_state {
    PCAP_THREAD_PACKET_OK = 0,
    PCAP_THREAD_PACKET_INVALID,
    PCAP_THREAD_PACKET_UNSUPPORTED,
    PCAP_THREAD_PACKET_UNPROCESSED,
    PCAP_THREAD_PACKET_INVALID_ETHER,
    PCAP_THREAD_PACKET_INVALID_LINUX_SLL,
    PCAP_THREAD_PACKET_INVALID_NULL,
    PCAP_THREAD_PACKET_INVALID_LOOP,
    PCAP_THREAD_PACKET_INVALID_IEEE802,
    PCAP_THREAD_PACKET_INVALID_GRE,
    PCAP_THREAD_PACKET_INVALID_IP,
    PCAP_THREAD_PACKET_INVALID_IPV4,
    PCAP_THREAD_PACKET_INVALID_IPV6,
    PCAP_THREAD_PACKET_INVALID_IPV6HDR,
    PCAP_THREAD_PACKET_INVALID_ICMP,
    PCAP_THREAD_PACKET_INVALID_ICMPV6,
    PCAP_THREAD_PACKET_INVALID_UDP,
    PCAP_THREAD_PACKET_INVALID_TCP,
    PCAP_THREAD_PACKET_IS_FRAGMENT,
    PCAP_THREAD_PACKET_INVALID_FRAGMENT,
    PCAP_THREAD_PACKET_ENOMEM,
    PCAP_THREAD_PACKET_EMUTEX,
    PCAP_THREAD_PACKET_FRAGMENTED_GREHDR,
    PCAP_THREAD_PACKET_FRAGMENTED_ICMPHDR,
    PCAP_THREAD_PACKET_FRAGMENTED_ICMPV6HDR,
    PCAP_THREAD_PACKET_FRAGMENTED_UDPHDR,
    PCAP_THREAD_PACKET_FRAGMENTED_TCPHDR,
    PCAP_THREAD_PACKET_INVALID_LINUX_SLL2
};

typedef struct pcap_thread_packet pcap_thread_packet_t;
struct pcap_thread_packet {
    unsigned short have_prevpkt : 1;
    unsigned short have_pkthdr : 1;
    unsigned short have_linux_sll : 1;
    unsigned short have_linux_sll2 : 1;
    unsigned short have_ethhdr : 1;
    unsigned short have_nullhdr : 1;
    unsigned short have_loophdr : 1;
    unsigned short have_ieee802hdr : 1;
    unsigned short have_grehdr : 1;
    unsigned short have_gre : 1;
    unsigned short have_iphdr : 1;
    unsigned short have_ip6hdr : 1;
    unsigned short have_ip6frag : 1;
    unsigned short have_ip6rtdst : 1;
    unsigned short have_icmphdr : 1;
    unsigned short have_icmpv6hdr : 1;
    unsigned short have_udphdr : 1;
    unsigned short have_tcphdr : 1;
    unsigned short have_tcpopts : 1;
    unsigned short have_ippadding : 1;
    unsigned short have_ip6padding : 1;

    const char*                    name;
    int                            dlt;
    pcap_thread_packet_t*          prevpkt;
    struct pcap_pkthdr             pkthdr;
    struct pcap_thread_linux_sll   linux_sll;
    struct pcap_thread_linux_sll2  linux_sll2;
    struct ether_header            ethhdr;
    struct pcap_thread_null_hdr    nullhdr;
    struct pcap_thread_loop_hdr    loophdr;
    struct pcap_thread_ieee802_hdr ieee802hdr;
    struct pcap_thread_gre_hdr     grehdr;
    struct pcap_thread_gre         gre;
    struct ip                      iphdr;
    struct ip6_hdr                 ip6hdr;
    struct ip6_frag                ip6frag;
    uint8_t                        ip6frag_payload;
    struct in6_addr                ip6rtdst;
    struct {
        u_int8_t  type;
        u_int8_t  code;
        u_int16_t checksum;
    } icmphdr;
    struct {
        u_int8_t  icmp6_type;
        u_int8_t  icmp6_code;
        u_int16_t icmp6_cksum;
    } icmpv6hdr;
    struct {
        union {
            struct {
                u_int16_t uh_sport;
                u_int16_t uh_dport;
                u_int16_t uh_ulen;
                u_int16_t uh_sum;
            };
            struct {
                u_int16_t source;
                u_int16_t dest;
                u_int16_t len;
                u_int16_t check;
            };
        };
    } udphdr;
    struct {
        union {
            struct {
                u_int16_t th_sport;
                u_int16_t th_dport;
                u_int32_t th_seq;
                u_int32_t th_ack;
#if __BYTE_ORDER == __LITTLE_ENDIAN
                u_int8_t th_x2 : 4;
                u_int8_t th_off : 4;
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
                u_int8_t th_off : 4;
                u_int8_t th_x2 : 4;
#endif
                u_int8_t  th_flags;
                u_int16_t th_win;
                u_int16_t th_sum;
                u_int16_t th_urp;
            };
            struct {
                u_int16_t source;
                u_int16_t dest;
                u_int32_t seq;
                u_int32_t ack_seq;
#if __BYTE_ORDER == __LITTLE_ENDIAN
                u_int16_t res1 : 4;
                u_int16_t doff : 4;
                u_int16_t fin : 1;
                u_int16_t syn : 1;
                u_int16_t rst : 1;
                u_int16_t psh : 1;
                u_int16_t ack : 1;
                u_int16_t urg : 1;
                u_int16_t res2 : 2;
#elif __BYTE_ORDER == __BIG_ENDIAN
                u_int16_t doff : 4;
                u_int16_t res1 : 4;
                u_int16_t res2 : 2;
                u_int16_t urg : 1;
                u_int16_t ack : 1;
                u_int16_t psh : 1;
                u_int16_t rst : 1;
                u_int16_t syn : 1;
                u_int16_t fin : 1;
#endif
                u_int16_t window;
                u_int16_t check;
                u_int16_t urg_ptr;
            };
        };
    } tcphdr;
    u_int8_t tcpopts[64];
    size_t   tcpopts_len;

    size_t ippadding;
    size_t ip6padding;

    pcap_thread_packet_state_t state;
};

typedef enum pcap_thread_queue_mode pcap_thread_queue_mode_t;
typedef struct pcap_thread          pcap_thread_t;
typedef void (*pcap_thread_callback_t)(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* pkt, const char* name, int dlt);
typedef void (*pcap_thread_layer_callback_t)(u_char* user, const pcap_thread_packet_t* packet, const u_char* payload, size_t length);
typedef void (*pcap_thread_stats_callback_t)(u_char* user, const struct pcap_stat* stats, const char* name, int dlt);
#ifndef HAVE_PCAP_DIRECTION_T
typedef int pcap_direction_t;
#endif
typedef struct pcap_thread_pcaplist    pcap_thread_pcaplist_t;
typedef enum pcap_thread_activate_mode pcap_thread_activate_mode_t;

enum pcap_thread_queue_mode {
    PCAP_THREAD_QUEUE_MODE_COND,
    PCAP_THREAD_QUEUE_MODE_WAIT,
    PCAP_THREAD_QUEUE_MODE_YIELD,
    PCAP_THREAD_QUEUE_MODE_DROP,
    PCAP_THREAD_QUEUE_MODE_DIRECT
};

enum pcap_thread_activate_mode {
    PCAP_THREAD_ACTIVATE_MODE_IMMEDIATE,
    PCAP_THREAD_ACTIVATE_MODE_DELAYED
};

#ifdef HAVE_PCAP_DIRECTION_T
#define PCAP_THREAD_T_INIT_DIRECTION_T 0,
#else
#define PCAP_THREAD_T_INIT_DIRECTION_T
#endif

#ifdef HAVE_PTHREAD
#define PCAP_THREAD_T_INIT_QUEUE PTHREAD_COND_INITIALIZER, PTHREAD_COND_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, \
                                 0, 0, 0, 0, 0, 0,
#else
#define PCAP_THREAD_T_INIT_QUEUE
#endif

#ifdef PCAP_TSTAMP_PRECISION_MICRO
#define PCAP_THREAD_T_INIT_PRECISION PCAP_TSTAMP_PRECISION_MICRO
#else
#define PCAP_THREAD_T_INIT_PRECISION 0
#endif

typedef void* (*pcap_thread_layer_callback_frag_new_t)(void* conf, u_char* user);
typedef void (*pcap_thread_layer_callback_frag_free_t)(void* ctx);
typedef pcap_thread_packet_state_t (*pcap_thread_layer_callback_frag_reassemble_t)(void* ctx, const pcap_thread_packet_t* packet, const u_char* payload, size_t length, pcap_thread_packet_t** whole_packet, const u_char** whole_payload, size_t* whole_length);
typedef void (*pcap_thread_layer_callback_frag_release_t)(void* ctx, const pcap_thread_packet_t* packet, const u_char* payload, size_t length);

/* clang-format off */
#define PCAP_THREAD_LAYER_CALLBACK_FRAG_T_INIT { \
    0, 0, 0, 0, 0, \
}
/* clang-format on */

typedef struct pcap_thread_layer_callback_frag pcap_thread_layer_callback_frag_t;
struct pcap_thread_layer_callback_frag {
    void* conf;
    pcap_thread_layer_callback_frag_new_t new;
    pcap_thread_layer_callback_frag_free_t       free;
    pcap_thread_layer_callback_frag_reassemble_t reassemble;
    pcap_thread_layer_callback_frag_release_t    release;
};

/* clang-format off */
#define PCAP_THREAD_T_INIT { \
    0, 0, 0, 0, \
    0, 1, 0, PCAP_THREAD_DEFAULT_QUEUE_MODE, PCAP_THREAD_DEFAULT_QUEUE_SIZE, \
    PCAP_THREAD_T_INIT_QUEUE \
    0, 0, 0, 0, PCAP_THREAD_DEFAULT_TIMEOUT, \
    0, 0, PCAP_THREAD_T_INIT_PRECISION, 0, \
    PCAP_THREAD_T_INIT_DIRECTION_T \
    0, 0, 0, 1, PCAP_NETMASK_UNKNOWN, \
    0, 0, \
    0, "", 0, 0, \
    { 0, 0 }, { 0, 0 }, \
    PCAP_THREAD_DEFAULT_ACTIVATE_MODE, \
    0, 0, 0, 0, 0, 0, 0, 0, 0, PCAP_THREAD_LAYER_CALLBACK_FRAG_T_INIT, 0, PCAP_THREAD_LAYER_CALLBACK_FRAG_T_INIT, 0, 0, 0, 0, \
    0 \
}
/* clang-format on */

struct pcap_thread {
    unsigned short have_timestamp_precision : 1;
    unsigned short have_timestamp_type : 1;
    unsigned short have_direction : 1;
    unsigned short was_stopped : 1;

    int                      running;
    int                      use_threads;
    int                      use_layers;
    pcap_thread_queue_mode_t queue_mode;
    size_t                   queue_size;

#ifdef HAVE_PTHREAD
    pthread_cond_t  have_packets;
    pthread_cond_t  can_write;
    pthread_mutex_t mutex;

    struct pcap_pkthdr*      pkthdr;
    u_char*                  pkt;
    pcap_thread_pcaplist_t** pcaplist_pkt;
    size_t                   read_pos;
    size_t                   write_pos;
    size_t                   pkts;
#endif

    int snapshot;
    int snaplen;
    int promiscuous;
    int monitor;
    int timeout;

    int buffer_size;
    int timestamp_type;
    int timestamp_precision;
    int immediate_mode;

#ifdef HAVE_PCAP_DIRECTION_T
    pcap_direction_t direction;
#endif

    char*       filter;
    size_t      filter_len;
    int         filter_errno;
    int         filter_optimize;
    bpf_u_int32 filter_netmask;

    pcap_thread_callback_t callback;
    pcap_thread_callback_t dropback;

    int                     status;
    char                    errbuf[PCAP_ERRBUF_SIZE];
    pcap_thread_pcaplist_t* pcaplist;
    pcap_thread_pcaplist_t* step;

    struct timeval timedrun;
    struct timeval timedrun_to;

    pcap_thread_activate_mode_t activate_mode;

    pcap_thread_layer_callback_t      callback_linux_sll;
    pcap_thread_layer_callback_t      callback_linux_sll2;
    pcap_thread_layer_callback_t      callback_ether;
    pcap_thread_layer_callback_t      callback_null;
    pcap_thread_layer_callback_t      callback_loop;
    pcap_thread_layer_callback_t      callback_ieee802;
    pcap_thread_layer_callback_t      callback_gre;
    pcap_thread_layer_callback_t      callback_ip;
    pcap_thread_layer_callback_t      callback_ipv4;
    pcap_thread_layer_callback_frag_t callback_ipv4_frag;
    pcap_thread_layer_callback_t      callback_ipv6;
    pcap_thread_layer_callback_frag_t callback_ipv6_frag;
    pcap_thread_layer_callback_t      callback_icmp;
    pcap_thread_layer_callback_t      callback_icmpv6;
    pcap_thread_layer_callback_t      callback_udp;
    pcap_thread_layer_callback_t      callback_tcp;

    pcap_thread_layer_callback_t callback_invalid;
};

#define PCAP_THREAD_SET_ERRBUF(x, y) strncpy(x->errbuf, y, sizeof(x->errbuf) - 1)

#ifdef HAVE_PTHREAD
#define PCAP_THREAD_PCAPLIST_T_INIT_THREAD 0,
#else
#define PCAP_THREAD_PCAPLIST_T_INIT_THREAD
#endif

/* clang-format off */
#define PCAP_THREAD_PCAPLIST_T_INIT { \
    0, 0, 0, \
    0, 0, 0, 0, 0, 0, 0, 0, \
    0, \
    PCAP_THREAD_PCAPLIST_T_INIT_THREAD \
    { 0, 0 }, \
    0, \
    0, { 0, 0 } \
}
/* clang-format on */

struct pcap_thread_pcaplist {
    unsigned short have_bpf : 1;
    unsigned short have_ipv4_frag_ctx : 1;
    unsigned short have_ipv6_frag_ctx : 1;

    pcap_thread_pcaplist_t* next;
    char*                   name;
    pcap_t*                 pcap;
    void*                   user;
    int                     running;
    int                     is_offline;
    void*                   ipv4_frag_ctx;
    void*                   ipv6_frag_ctx;

    pcap_thread_t* pcap_thread;

#ifdef HAVE_PTHREAD
    pthread_t thread;
#endif

    struct bpf_program bpf;

    pcap_thread_callback_t layer_callback;

    int             timedrun;
    struct timespec end;
};

const char* pcap_thread_version_str(void);

int pcap_thread_version_major(void);
int pcap_thread_version_minor(void);
int pcap_thread_version_patch(void);

pcap_thread_t* pcap_thread_create(void);
void           pcap_thread_free(pcap_thread_t* pcap_thread);

int                         pcap_thread_use_threads(const pcap_thread_t* pcap_thread);
int                         pcap_thread_set_use_threads(pcap_thread_t* pcap_thread, const int use_threads);
int                         pcap_thread_use_layers(const pcap_thread_t* pcap_thread);
int                         pcap_thread_set_use_layers(pcap_thread_t* pcap_thread, const int use_layers);
pcap_thread_queue_mode_t    pcap_thread_queue_mode(const pcap_thread_t* pcap_thread);
int                         pcap_thread_set_queue_mode(pcap_thread_t* pcap_thread, const pcap_thread_queue_mode_t queue_mode);
struct timeval              pcap_thread_queue_wait(const pcap_thread_t* pcap_thread);
int                         pcap_thread_set_queue_wait(pcap_thread_t* pcap_thread, const struct timeval queue_wait);
pcap_thread_queue_mode_t    pcap_thread_callback_queue_mode(const pcap_thread_t* pcap_thread);
int                         pcap_thread_set_callback_queue_mode(pcap_thread_t* pcap_thread, const pcap_thread_queue_mode_t callback_queue_mode);
struct timeval              pcap_thread_callback_queue_wait(const pcap_thread_t* pcap_thread);
int                         pcap_thread_set_callback_queue_wait(pcap_thread_t* pcap_thread, const struct timeval callback_queue_wait);
int                         pcap_thread_snapshot(const pcap_thread_t* pcap_thread);
int                         pcap_thread_snaplen(const pcap_thread_t* pcap_thread);
int                         pcap_thread_set_snaplen(pcap_thread_t* pcap_thread, const int snaplen);
int                         pcap_thread_promiscuous(const pcap_thread_t* pcap_thread);
int                         pcap_thread_set_promiscuous(pcap_thread_t* pcap_thread, const int promiscuous);
int                         pcap_thread_monitor(const pcap_thread_t* pcap_thread);
int                         pcap_thread_set_monitor(pcap_thread_t* pcap_thread, const int monitor);
int                         pcap_thread_timeout(const pcap_thread_t* pcap_thread);
int                         pcap_thread_set_timeout(pcap_thread_t* pcap_thread, const int timeout);
int                         pcap_thread_buffer_size(const pcap_thread_t* pcap_thread);
int                         pcap_thread_set_buffer_size(pcap_thread_t* pcap_thread, const int buffer_size);
int                         pcap_thread_timestamp_type(const pcap_thread_t* pcap_thread);
int                         pcap_thread_set_timestamp_type(pcap_thread_t* pcap_thread, const int timestamp_type);
int                         pcap_thread_timestamp_precision(const pcap_thread_t* pcap_thread);
int                         pcap_thread_set_timestamp_precision(pcap_thread_t* pcap_thread, const int timestamp_precision);
int                         pcap_thread_immediate_mode(const pcap_thread_t* pcap_thread);
int                         pcap_thread_set_immediate_mode(pcap_thread_t* pcap_thread, const int immediate_mode);
pcap_direction_t            pcap_thread_direction(const pcap_thread_t* pcap_thread);
int                         pcap_thread_set_direction(pcap_thread_t* pcap_thread, const pcap_direction_t direction);
const char*                 pcap_thread_filter(const pcap_thread_t* pcap_thread);
int                         pcap_thread_set_filter(pcap_thread_t* pcap_thread, const char* filter, const size_t filter_len);
int                         pcap_thread_clear_filter(pcap_thread_t* pcap_thread);
int                         pcap_thread_filter_errno(const pcap_thread_t* pcap_thread);
int                         pcap_thread_filter_optimize(const pcap_thread_t* pcap_thread);
int                         pcap_thread_set_filter_optimize(pcap_thread_t* pcap_thread, const int filter_optimize);
bpf_u_int32                 pcap_thread_filter_netmask(const pcap_thread_t* pcap_thread);
int                         pcap_thread_set_filter_netmask(pcap_thread_t* pcap_thread, const bpf_u_int32 filter_netmask);
struct timeval              pcap_thread_timedrun(const pcap_thread_t* pcap_thread);
int                         pcap_thread_set_timedrun(pcap_thread_t* pcap_thread, const struct timeval timedrun);
struct timeval              pcap_thread_timedrun_to(const pcap_thread_t* pcap_thread);
int                         pcap_thread_set_timedrun_to(pcap_thread_t* pcap_thread, const struct timeval timedrun_to);
pcap_thread_activate_mode_t pcap_thread_activate_mode(const pcap_thread_t* pcap_thread);
int                         pcap_thread_set_activate_mode(pcap_thread_t* pcap_thread, const pcap_thread_activate_mode_t activate_mode);
int                         pcap_thread_was_stopped(const pcap_thread_t* pcap_thread);

size_t pcap_thread_queue_size(const pcap_thread_t* pcap_thread);
int    pcap_thread_set_queue_size(pcap_thread_t* pcap_thread, const size_t queue_size);

int pcap_thread_set_callback(pcap_thread_t* pcap_thread, pcap_thread_callback_t callback);
int pcap_thread_set_dropback(pcap_thread_t* pcap_thread, pcap_thread_callback_t dropback);

int pcap_thread_set_callback_linux_sll(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_linux_sll);
int pcap_thread_set_callback_linux_sll2(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_linux_sll2);
int pcap_thread_set_callback_ether(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_ether);
int pcap_thread_set_callback_null(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_null);
int pcap_thread_set_callback_loop(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_loop);
int pcap_thread_set_callback_ieee802(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_ieee802);
int pcap_thread_set_callback_gre(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_gre);
int pcap_thread_set_callback_ip(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_ip);
int pcap_thread_set_callback_ipv4(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_ipv4);
int pcap_thread_set_callback_ipv4_frag(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_frag_t callback_ipv4_frag);
int pcap_thread_set_callback_ipv6(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_ipv6);
int pcap_thread_set_callback_ipv6_frag(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_frag_t callback_ipv6_frag);
int pcap_thread_set_callback_icmp(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_icmp);
int pcap_thread_set_callback_icmpv6(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_icmpv6);
int pcap_thread_set_callback_udp(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_udp);
int pcap_thread_set_callback_tcp(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_tcp);
int pcap_thread_set_callback_invalid(pcap_thread_t* pcap_thread, pcap_thread_layer_callback_t callback_tcp);

int pcap_thread_open(pcap_thread_t* pcap_thread, const char* device, void* user);
int pcap_thread_open_offline(pcap_thread_t* pcap_thread, const char* file, void* user);
int pcap_thread_add(pcap_thread_t* pcap_thread, const char* name, pcap_t* pcap, void* user);
int pcap_thread_activate(pcap_thread_t* pcap_thread);
int pcap_thread_close(pcap_thread_t* pcap_thread);

int pcap_thread_run(pcap_thread_t* pcap_thread);
int pcap_thread_next(pcap_thread_t* pcap_thread);
int pcap_thread_next_reset(pcap_thread_t* pcap_thread);
int pcap_thread_stop(pcap_thread_t* pcap_thread);

int pcap_thread_stats(pcap_thread_t* pcap_thread, pcap_thread_stats_callback_t callback, u_char* user);

int         pcap_thread_status(const pcap_thread_t* pcap_thread);
const char* pcap_thread_errbuf(const pcap_thread_t* pcap_thread);
const char* pcap_thread_strerr(int error);

#ifdef __cplusplus
}
#endif

#endif /* __pcap_thread_h */
