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

#include "pcap_thread_ext_frag.h"

#include <stdlib.h>
#include <string.h>
#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

#ifndef PCAP_THREAD_EXT_FRAG_TRACE
#define PCAP_THREAD_EXT_FRAG_TRACE 0
#endif

/*
 * Forward declares for callbacks
 */

static void* pcap_thread_layer_callback_frag_new(void* conf, u_char* user);
static void pcap_thread_layer_callback_frag_free(void* _ctx);
static pcap_thread_packet_state_t pcap_thread_layer_callback_frag_reassemble(void* _ctx, const pcap_thread_packet_t* packet, const u_char* payload, size_t length, pcap_thread_packet_t** whole_packet, const u_char** whole_payload, size_t* whole_length);
static void pcap_thread_layer_callback_frag_release(void* _ctx, const pcap_thread_packet_t* packet, const u_char* payload, size_t length);

/*
 * Create/Free
 */

static pcap_thread_ext_frag_conf_t _conf_defaults = PCAP_THREAD_EXT_FRAG_CONF_T_INIT;

pcap_thread_ext_frag_conf_t* pcap_thread_ext_frag_conf_new(void)
{
    pcap_thread_ext_frag_conf_t* conf = calloc(1, sizeof(pcap_thread_ext_frag_conf_t));
    if (conf) {
        memcpy(conf, &_conf_defaults, sizeof(pcap_thread_ext_frag_conf_t));
    }

    return conf;
}

void pcap_thread_ext_frag_conf_free(pcap_thread_ext_frag_conf_t* conf)
{
    if (conf) {
        free(conf);
    }
}

/*
 * Get/Set
 */

int pcap_thread_ext_frag_conf_reject_overlap(const pcap_thread_ext_frag_conf_t* conf)
{
    if (!conf) {
        return 0;
    }

    return conf->reject_overlap;
}

int pcap_thread_ext_frag_conf_set_reject_overlap(pcap_thread_ext_frag_conf_t* conf, const int reject_overlap)
{
    if (!conf) {
        return PCAP_THREAD_EINVAL;
    }

    conf->reject_overlap = reject_overlap ? 1 : 0;

    return PCAP_THREAD_OK;
}

int pcap_thread_ext_frag_conf_check_timeout(const pcap_thread_ext_frag_conf_t* conf)
{
    if (!conf) {
        return 0;
    }

    return conf->check_timeout;
}

int pcap_thread_ext_frag_conf_set_check_timeout(pcap_thread_ext_frag_conf_t* conf, const int check_timeout)
{
    if (!conf) {
        return PCAP_THREAD_EINVAL;
    }

    conf->check_timeout = check_timeout ? 1 : 0;

    return PCAP_THREAD_OK;
}

pcap_thread_ext_frag_reassemble_mode_t pcap_thread_ext_frag_conf_reassemble_mode(const pcap_thread_ext_frag_conf_t* conf)
{
    if (!conf) {
        return PCAP_THREAD_EXT_FRAG_REASSEMBLE_RFC791;
    }

    return conf->reassemble_mode;
}

int pcap_thread_ext_frag_conf_set_reassemble_mode(pcap_thread_ext_frag_conf_t* conf, const pcap_thread_ext_frag_reassemble_mode_t reassemble_mode)
{
    if (!conf) {
        return PCAP_THREAD_EINVAL;
    }

    switch (reassemble_mode) {
    case PCAP_THREAD_EXT_FRAG_REASSEMBLE_RFC791:
    case PCAP_THREAD_EXT_FRAG_REASSEMBLE_BSD:
        break;
    case PCAP_THREAD_EXT_FRAG_REASSEMBLE_RFC815:
    /* TODO: Implement */
    default:
        return PCAP_THREAD_EINVAL;
    }

    conf->reassemble_mode = reassemble_mode;

    return PCAP_THREAD_OK;
}

size_t pcap_thread_ext_frag_conf_fragments(const pcap_thread_ext_frag_conf_t* conf)
{
    if (!conf) {
        return -1;
    }

    return conf->fragments;
}

int pcap_thread_ext_frag_conf_set_fragments(pcap_thread_ext_frag_conf_t* conf, const size_t fragments)
{
    if (!conf) {
        return PCAP_THREAD_EINVAL;
    }

    conf->fragments = fragments;

    return PCAP_THREAD_OK;
}

size_t pcap_thread_ext_frag_conf_per_packet(const pcap_thread_ext_frag_conf_t* conf)
{
    if (!conf) {
        return -1;
    }

    return conf->per_packet;
}

int pcap_thread_ext_frag_conf_set_per_packet(pcap_thread_ext_frag_conf_t* conf, const size_t per_packet)
{
    if (!conf) {
        return PCAP_THREAD_EINVAL;
    }

    conf->per_packet = per_packet;

    return PCAP_THREAD_OK;
}

struct timeval pcap_thread_ext_frag_conf_timeout(const pcap_thread_ext_frag_conf_t* conf)
{
    if (!conf) {
        struct timeval ret = { 0, 0 };
        return ret;
    }

    return conf->timeout;
}

int pcap_thread_ext_frag_conf_set_timeout(pcap_thread_ext_frag_conf_t* conf, const struct timeval timeout)
{
    if (!conf) {
        return PCAP_THREAD_EINVAL;
    }

    conf->timeout = timeout;

    return PCAP_THREAD_OK;
}

pcap_thread_ext_frag_callback_t pcap_thread_ext_frag_conf_overlap_callback(const pcap_thread_ext_frag_conf_t* conf)
{
    if (!conf) {
        return 0;
    }

    return conf->overlap_callback;
}

int pcap_thread_ext_frag_conf_set_overlap_callback(pcap_thread_ext_frag_conf_t* conf, pcap_thread_ext_frag_callback_t overlap_callback)
{
    if (!conf) {
        return PCAP_THREAD_EINVAL;
    }

    conf->overlap_callback = overlap_callback;

    return PCAP_THREAD_OK;
}

pcap_thread_ext_frag_callback_t pcap_thread_ext_frag_conf_timeout_callback(const pcap_thread_ext_frag_conf_t* conf)
{
    if (!conf) {
        return 0;
    }

    return conf->timeout_callback;
}

int pcap_thread_ext_frag_conf_set_timeout_callback(pcap_thread_ext_frag_conf_t* conf, pcap_thread_ext_frag_callback_t timeout_callback)
{
    if (!conf) {
        return PCAP_THREAD_EINVAL;
    }

    conf->timeout_callback = timeout_callback;

    return PCAP_THREAD_OK;
}

/*
 * Init
 */

pcap_thread_layer_callback_frag_t pcap_thread_ext_frag_layer_callback(pcap_thread_ext_frag_conf_t* conf)
{
    pcap_thread_layer_callback_frag_t callback = PCAP_THREAD_LAYER_CALLBACK_FRAG_T_INIT;

    if (conf) {
        callback.conf       = (void*)conf;
        callback.new        = pcap_thread_layer_callback_frag_new;
        callback.free       = pcap_thread_layer_callback_frag_free;
        callback.reassemble = pcap_thread_layer_callback_frag_reassemble;
        callback.release    = pcap_thread_layer_callback_frag_release;
    }

    return callback;
}

/*
 * Callbacks
 */

#if PCAP_THREAD_EXT_FRAG_TRACE
#include <stdio.h>
#define layer_trace(msg) printf("LT %s:%d: " msg "\n", __FILE__, __LINE__)
#define layer_tracef(msg, args...) printf("LT %s:%d: " msg "\n", __FILE__, __LINE__, args)
#else
#define layer_trace(msg)
#define layer_tracef(msg, args...)
#endif

/* TODO:
typedef struct _hole _hole_t;
struct _hole {
    _hole_t* next;

    size_t first, last;
};
*/

#ifdef HAVE_PTHREAD
#define PCAP_THREAD_EXT_FRAG_CTX_T_INIT_MUTEX PTHREAD_MUTEX_INITIALIZER,
#else
#define PCAP_THREAD_EXT_FRAG_CTX_T_INIT_MUTEX
#endif

/* clang-format off */
#define PCAP_THREAD_EXT_FRAG_CTX_T_INIT { \
    PCAP_THREAD_EXT_FRAG_CTX_T_INIT_MUTEX \
    PCAP_THREAD_EXT_FRAG_CONF_T_INIT, 0, 0 \
}
/* clang-format on */

typedef struct _ctx _ctx_t;
struct _ctx {
#ifdef HAVE_PTHREAD
    pthread_mutex_t mutex;
#endif
    pcap_thread_ext_frag_conf_t       conf;
    pcap_thread_ext_frag_fragments_t* fragments;
    size_t                            num_fragments;
};

static _ctx_t _ctx_defaults = PCAP_THREAD_EXT_FRAG_CTX_T_INIT;

static void* pcap_thread_layer_callback_frag_new(void* conf, u_char* user)
{
    _ctx_t* ctx = calloc(1, sizeof(_ctx_t));
    if (ctx) {
        layer_tracef("new ctx %p", ctx);
        memcpy(ctx, &_ctx_defaults, sizeof(_ctx_t));
        if (conf) {
            memcpy(&(ctx->conf), conf, sizeof(pcap_thread_ext_frag_conf_t));
        }
    }

    return ctx;
}

static void pcap_thread_layer_callback_frag_free(void* _ctx)
{
    _ctx_t* ctx = (_ctx_t*)_ctx;
    if (ctx) {
        layer_tracef("free ctx %p", ctx);
        while (ctx->fragments) {
            pcap_thread_ext_frag_fragments_t* frags = ctx->fragments;
            ctx->fragments                          = frags->next;

            while (frags->fragments) {
                pcap_thread_ext_frag_fragment_t* frag = frags->fragments;
                frags->fragments                      = frag->next;

                if (frag->payload) {
                    free(frag->payload);
                }
                free(frag);
            }

            if (frags->payload) {
                free(frags->payload);
            }
            free(frags);
        }
    }
}

static pcap_thread_packet_state_t reassemble(_ctx_t* ctx, const pcap_thread_packet_t* packet, pcap_thread_packet_t** whole_packet, const u_char** whole_payload, size_t* whole_length, pcap_thread_ext_frag_fragments_t* frags, pcap_thread_ext_frag_fragment_t* frag)
{
    pcap_thread_ext_frag_fragment_t *f, *f_prev;
    int                              missing_frag = 0;
    /* TODO:
    int rfc815_seen_no_more_frags = 0;
    */

    if ((frag->offset + frag->length) > frags->length) {
        frags->length = frag->offset + frag->length;
    }

    layer_tracef("new frag len %lu off %lu mf %d (frags len %lu)", frag->length, frag->offset, frag->flag_more_fragments, frags->length);

    /* Place the fragment in the fragments list */
    switch (ctx->conf.reassemble_mode) {
    case PCAP_THREAD_EXT_FRAG_REASSEMBLE_RFC791:
        for (f_prev = 0, f = frags->fragments; f; f_prev = f, f = f->next) {
            layer_tracef("checking frag %p len %lu off %lu mf %d next %p", f, f->length, f->offset, f->flag_more_fragments, f->next);

            if (f->offset > frag->offset) {
                if (f_prev) {
                    f_prev->next = frag;
                } else {
                    frags->fragments = frag;
                }
                frag->next = f;
                f          = frag;
                break;
            }
            if (f_prev && (f_prev->offset + f_prev->length) < f->offset) {
                missing_frag = 1;
            }
        }
        if (!f) {
            if (f_prev) {
                f_prev->next = frag;
                if ((f_prev->offset + f_prev->length) < frag->offset) {
                    missing_frag = 1;
                }
            } else {
                frags->fragments = frag;
            }
            /* New frag is now last frag */
            f_prev = frag;
        } else if (!missing_frag) {
            for (; f; f_prev = f, f = f->next) {
                layer_tracef("checking frag %p len %lu off %lu mf %d next %p", f, f->length, f->offset, f->flag_more_fragments, f->next);
                if (f_prev && (f_prev->offset + f_prev->length) < f->offset) {
                    missing_frag = 1;
                    break;
                }
            }
        }
        /*
         * If first is not offset zero or last have more fragments flag,
         * we are missing fragments.
         */
        if (!missing_frag && (frags->fragments->offset || f_prev->flag_more_fragments)) {
            missing_frag = 1;
        }
        break;
    case PCAP_THREAD_EXT_FRAG_REASSEMBLE_RFC815:
        /* TODO:
        for (f_prev = 0, f = frags->fragments; f; f_prev = f, f = f->next) {
            layer_tracef("checking frag %p len %lu off %lu mf %d next %p", f, f->length, f->offset, f->flag_more_fragments, f->next);

            if (!f->flag_more_fragments) {
                rfc815_seen_no_more_frags = 1;
            }
        }
        */
        break;
    case PCAP_THREAD_EXT_FRAG_REASSEMBLE_BSD:
        for (f_prev = 0, f = frags->fragments; f; f_prev = f, f = f->next) {
            layer_tracef("checking frag %p len %lu off %lu mf %d next %p", f, f->length, f->offset, f->flag_more_fragments, f->next);

            if (f->offset > frag->offset) {
                if (f_prev) {
                    f_prev->next = frag;
                } else {
                    frags->fragments = frag;
                }
                frag->next = f;
                f          = frag;
                break;
            }
            if (f_prev && (f->offset + f->length) < f_prev->offset) {
                missing_frag = 1;
            }
        }
        if (!f) {
            if (f_prev) {
                f_prev->next = frag;
                if ((frag->offset + frag->length) < f_prev->offset) {
                    missing_frag = 1;
                }
            } else {
                frags->fragments = frag;
            }
        } else if (!missing_frag) {
            for (; f; f_prev = f, f = f->next) {
                layer_tracef("checking frag %p len %lu off %lu mf %d next %p", f, f->length, f->offset, f->flag_more_fragments, f->next);
                if (f_prev && (f->offset + f->length) < f_prev->offset) {
                    missing_frag = 1;
                    break;
                }
            }
        }
        /*
         * If first (last on list) is not offset zero or last (first on
         * list) have more fragments flag, we are missing fragments.
         */
        if (!missing_frag && (f_prev->offset || frags->fragments->flag_more_fragments)) {
            missing_frag = 1;
        }
        break;
    }
    frags->num_fragments++;

    if (missing_frag) {
        layer_trace("need more frags");
        return PCAP_THREAD_PACKET_OK;
    }

    if (!frags->length) {
        layer_trace("frags complete but no size");
        return PCAP_THREAD_PACKET_INVALID_FRAGMENT;
    }

    if (ctx->conf.reject_overlap) {
        switch (ctx->conf.reassemble_mode) {
        case PCAP_THREAD_EXT_FRAG_REASSEMBLE_RFC791:
            for (f_prev = 0, f = frags->fragments; f; f_prev = f, f = f->next) {
                layer_tracef("checking frag %p len %lu off %lu mf %d next %p", f, f->length, f->offset, f->flag_more_fragments, f->next);
                if (f_prev && (f_prev->offset + f_prev->length) > f->offset) {
                    layer_trace("overlapping fragment");
                    if (ctx->conf.overlap_callback)
                        ctx->conf.overlap_callback(packet, frag->payload, frag->length, frags);
                    return PCAP_THREAD_PACKET_INVALID_FRAGMENT;
                }
            }
            break;
        case PCAP_THREAD_EXT_FRAG_REASSEMBLE_RFC815:
            /* TODO:
            */
            break;
        case PCAP_THREAD_EXT_FRAG_REASSEMBLE_BSD:
            for (f_prev = 0, f = frags->fragments; f; f_prev = f, f = f->next) {
                layer_tracef("checking frag %p len %lu off %lu mf %d next %p", f, f->length, f->offset, f->flag_more_fragments, f->next);
                if (f_prev && (f->offset + f->length) > f_prev->offset) {
                    layer_trace("overlapping fragment");
                    if (ctx->conf.overlap_callback)
                        ctx->conf.overlap_callback(packet, frag->payload, frag->length, frags);
                    return PCAP_THREAD_PACKET_INVALID_FRAGMENT;
                }
            }
            break;
        }
    }

    /*
     * Reassemble packet
     */
    if (!(frags->payload = calloc(1, frags->length))) {
        layer_trace("nomem frags payload");
        return PCAP_THREAD_PACKET_ENOMEM;
    }
    for (f = frags->fragments; f; f = f->next) {
        memcpy(frags->payload + f->offset, f->payload, f->length);
    }

    frags->packet.name   = packet->name;
    frags->packet.dlt    = packet->dlt;
    frags->packet.pkthdr = packet->pkthdr;
    /*
     * We add the total payload length minus current fragment, since it is
     * already included, to the pkthdr lengths in order to return correct
     * total packet length (header + payload).
     */
    frags->packet.pkthdr.len += frags->length - frag->length;
    frags->packet.pkthdr.caplen += frags->length - frag->length;
    frags->packet.have_pkthdr = packet->have_pkthdr;

    *whole_packet  = &(frags->packet);
    *whole_payload = frags->payload;
    *whole_length  = frags->length;

    return PCAP_THREAD_PACKET_OK;
}

static pcap_thread_packet_state_t reassemble_ipv4(_ctx_t* ctx, const pcap_thread_packet_t* packet, const u_char* payload, size_t length, pcap_thread_packet_t** whole_packet, const u_char** whole_payload, size_t* whole_length)
{
    pcap_thread_ext_frag_fragments_t *frags, *frags_prev;
    pcap_thread_ext_frag_fragment_t*  frag;

    if (!packet->have_pkthdr) {
        layer_trace("no pkthdr");
        return PCAP_THREAD_PACKET_INVALID;
    }

    layer_tracef("ipv4 ctx %p", ctx);

    /* Find packet fragments */
    for (frags_prev = 0, frags = ctx->fragments; frags; frags_prev = frags, frags = frags->next) {
        if (frags->packet.have_iphdr
            && packet->iphdr.ip_id == frags->packet.iphdr.ip_id
            && packet->iphdr.ip_p == frags->packet.iphdr.ip_p
            && packet->iphdr.ip_src.s_addr == frags->packet.iphdr.ip_src.s_addr
            && packet->iphdr.ip_dst.s_addr == frags->packet.iphdr.ip_dst.s_addr) {

            layer_tracef("frags %d found", packet->iphdr.ip_id);

            /* Found it, remove from list */
            if (frags_prev) {
                frags_prev->next = frags->next;
            }
            if (ctx->fragments == frags) {
                ctx->fragments = frags->next;
            }
            frags->next = 0;
            break;
        }
    }

    /* Check if frags is timed out */
    if (ctx->conf.check_timeout && frags) {
        struct timeval ts;

        ts = frags->packet.pkthdr.ts;
        ts.tv_sec += ctx->conf.timeout.tv_sec;
        ts.tv_usec += ctx->conf.timeout.tv_usec;
        ts.tv_usec %= 1000000;
        if (packet->pkthdr.ts.tv_sec > ts.tv_sec
            || (packet->pkthdr.ts.tv_sec == ts.tv_sec
                   && packet->pkthdr.ts.tv_usec > ts.tv_usec)) {

            pcap_thread_ext_frag_fragment_t* f;

            layer_tracef("frags timed out (last: %lu.%lu, this: %lu.%lu)",
                frags->packet.pkthdr.ts.tv_sec, frags->packet.pkthdr.ts.tv_usec,
                packet->pkthdr.ts.tv_sec, packet->pkthdr.ts.tv_usec);

            if (ctx->conf.timeout_callback)
                ctx->conf.timeout_callback(packet, payload, length, frags);

            for (f = frags->fragments; f;) {
                frag = f;
                f    = f->next;
                if (frag->payload) {
                    free(frag->payload);
                }
                free(frag);
            }

            if (frags->payload) {
                free(frags->payload);
            }
            free(frags);
            frags = 0;
        } else {
            frags->packet.pkthdr.ts = packet->pkthdr.ts;
        }
    }

    /* No fragments found, create new */
    if (!frags) {
        if (ctx->num_fragments >= ctx->conf.fragments) {
            layer_trace("too many frags");
            return PCAP_THREAD_PACKET_INVALID_FRAGMENT;
        }

        if (!(frags = calloc(1, sizeof(pcap_thread_ext_frag_fragments_t)))) {
            layer_trace("nomem frags");
            return PCAP_THREAD_PACKET_ENOMEM;
        }

        layer_tracef("new frags %d", packet->iphdr.ip_id);

        // TODO: How to handle prevpkt
        memcpy(&(frags->packet.iphdr), &(packet->iphdr), sizeof(struct ip));
        frags->packet.have_iphdr = 1;
        frags->packet.pkthdr.ts  = packet->pkthdr.ts;

        ctx->num_fragments++;
    }
    /* Put the fragments first on the list */
    frags->next    = ctx->fragments;
    ctx->fragments = frags;

    if (frags->payload) {
        layer_trace("already reassembled");
        return PCAP_THREAD_PACKET_INVALID_FRAGMENT;
    }

    if (frags->num_fragments >= ctx->conf.per_packet) {
        layer_trace("too many frags frag");
        return PCAP_THREAD_PACKET_INVALID_FRAGMENT;
    }

    /* Allocate for the new fragment */
    if (!(frag = calloc(1, sizeof(pcap_thread_ext_frag_fragment_t)))) {
        layer_trace("nomem frag");
        return PCAP_THREAD_PACKET_ENOMEM;
    }
    if (!(frag->payload = calloc(1, length))) {
        free(frag);
        layer_trace("nomem frag");
        return PCAP_THREAD_PACKET_ENOMEM;
    }
    memcpy(frag->payload, payload, length);
    frag->length              = length;
    frag->offset              = (packet->iphdr.ip_off & 0x1fff) * 8;
    frag->flag_more_fragments = packet->iphdr.ip_off & 0x2000 ? 1 : 0;

    return reassemble(ctx, packet, whole_packet, whole_payload, whole_length, frags, frag);
}

static pcap_thread_packet_state_t reassemble_ipv6(_ctx_t* ctx, const pcap_thread_packet_t* packet, const u_char* payload, size_t length, pcap_thread_packet_t** whole_packet, const u_char** whole_payload, size_t* whole_length)
{
    pcap_thread_ext_frag_fragments_t *frags, *frags_prev;
    pcap_thread_ext_frag_fragment_t*  frag;

    layer_tracef("ipv6 ctx %p", ctx);

    /* Find packet fragments */
    for (frags_prev = 0, frags = ctx->fragments; frags; frags_prev = frags, frags = frags->next) {
        if (frags->packet.have_ip6hdr
            && packet->ip6frag.ip6f_ident == frags->packet.ip6frag.ip6f_ident
            && !memcmp(&(packet->ip6hdr.ip6_src), &(frags->packet.ip6hdr.ip6_src), sizeof(struct in6_addr))
            && ((!packet->have_ip6rtdst && !memcmp(&(packet->ip6hdr.ip6_dst), &(frags->packet.ip6hdr.ip6_dst), sizeof(struct in6_addr)))
                   || (packet->have_ip6rtdst && !memcmp(&(packet->ip6rtdst), &(frags->packet.ip6hdr.ip6_dst), sizeof(struct in6_addr))))) {

            layer_tracef("frags %x found", packet->ip6frag.ip6f_ident);

            /* Found it, remove from list */
            if (frags_prev) {
                frags_prev->next = frags->next;
            }
            if (ctx->fragments == frags) {
                ctx->fragments = frags->next;
            }
            frags->next = 0;
            break;
        }
    }

    /* Check if frags is timed out */
    if (ctx->conf.check_timeout && frags) {
        struct timeval ts;

        ts = frags->packet.pkthdr.ts;
        ts.tv_sec += ctx->conf.timeout.tv_sec;
        ts.tv_usec += ctx->conf.timeout.tv_usec;
        ts.tv_usec %= 1000000;
        if (packet->pkthdr.ts.tv_sec > ts.tv_sec
            || (packet->pkthdr.ts.tv_sec == ts.tv_sec
                   && packet->pkthdr.ts.tv_usec > ts.tv_usec)) {

            pcap_thread_ext_frag_fragment_t* f;

            layer_tracef("frags timed out (last: %lu.%lu, this: %lu.%lu)",
                frags->packet.pkthdr.ts.tv_sec, frags->packet.pkthdr.ts.tv_usec,
                packet->pkthdr.ts.tv_sec, packet->pkthdr.ts.tv_usec);

            if (ctx->conf.timeout_callback)
                ctx->conf.timeout_callback(packet, payload, length, frags);

            for (f = frags->fragments; f;) {
                frag = f;
                f    = f->next;
                if (frag->payload) {
                    free(frag->payload);
                }
                free(frag);
            }

            if (frags->payload) {
                free(frags->payload);
            }
            free(frags);
            frags = 0;
        } else {
            frags->packet.pkthdr.ts = packet->pkthdr.ts;
        }
    }

    /* No fragments found, create new */
    if (!frags) {
        if (ctx->num_fragments >= ctx->conf.fragments) {
            layer_trace("too many frags");
            return PCAP_THREAD_PACKET_INVALID_FRAGMENT;
        }

        if (!(frags = calloc(1, sizeof(pcap_thread_ext_frag_fragments_t)))) {
            layer_trace("nomem frags");
            return PCAP_THREAD_PACKET_ENOMEM;
        }

        layer_tracef("new frags %x", packet->ip6frag.ip6f_ident);

        // TODO: How to handle prevpkt
        memcpy(&(frags->packet.ip6hdr), &(packet->ip6hdr), sizeof(struct ip6_hdr));
        frags->packet.have_ip6hdr = 1;
        memcpy(&(frags->packet.ip6frag), &(packet->ip6frag), sizeof(struct ip6_frag));
        frags->packet.have_ip6frag    = 1;
        frags->packet.ip6frag_payload = packet->ip6frag_payload;
        if (packet->have_ip6rtdst) {
            frags->packet.ip6hdr.ip6_dst = packet->ip6rtdst;
        }
        frags->packet.pkthdr.ts = packet->pkthdr.ts;

        ctx->num_fragments++;
    } else {
        if (frags->packet.ip6frag_payload != packet->ip6frag_payload) {
            layer_trace("wrong payload");
            return PCAP_THREAD_PACKET_INVALID_FRAGMENT;
        }
    }
    /* Put the fragments first on the list */
    frags->next    = ctx->fragments;
    ctx->fragments = frags;

    if (frags->payload) {
        layer_trace("already reassembled");
        return PCAP_THREAD_PACKET_INVALID_FRAGMENT;
    }

    if (frags->num_fragments >= ctx->conf.per_packet) {
        layer_trace("too many frags frag");
        return PCAP_THREAD_PACKET_INVALID_FRAGMENT;
    }

    /* Allocate for the new fragment */
    if (!(frag = calloc(1, sizeof(pcap_thread_ext_frag_fragment_t)))) {
        layer_trace("nomem frag");
        return PCAP_THREAD_PACKET_ENOMEM;
    }
    if (!(frag->payload = calloc(1, length))) {
        free(frag);
        layer_trace("nomem frag");
        return PCAP_THREAD_PACKET_ENOMEM;
    }
    memcpy(frag->payload, payload, length);
    frag->length              = length;
    frag->offset              = ((packet->ip6frag.ip6f_offlg & 0xfff8) >> 3) * 8;
    frag->flag_more_fragments = packet->ip6frag.ip6f_offlg & 0x1 ? 1 : 0;

    return reassemble(ctx, packet, whole_packet, whole_payload, whole_length, frags, frag);
}

#ifdef HAVE_PTHREAD /* _release() is only used when mutex functions fails */
static void _release(_ctx_t* ctx, const pcap_thread_packet_t* packet)
{
    pcap_thread_ext_frag_fragments_t *frags, *frags_prev;

    layer_tracef("release ctx %p", ctx);

    /* Find packet fragments */
    for (frags_prev = 0, frags = ctx->fragments; frags; frags_prev = frags, frags = frags->next) {
        if (frags->packet.have_iphdr
            && packet->iphdr.ip_id == frags->packet.iphdr.ip_id
            && packet->iphdr.ip_p == frags->packet.iphdr.ip_p
            && packet->iphdr.ip_src.s_addr == frags->packet.iphdr.ip_src.s_addr
            && packet->iphdr.ip_dst.s_addr == frags->packet.iphdr.ip_dst.s_addr) {

            layer_tracef("release frags %d", packet->iphdr.ip_id);
            break;
        } else if (frags->packet.have_ip6hdr
                   && packet->ip6frag.ip6f_ident == frags->packet.ip6frag.ip6f_ident
                   && !memcmp(&(packet->ip6hdr.ip6_src), &(frags->packet.ip6hdr.ip6_src), sizeof(struct in6_addr))
                   && ((!packet->have_ip6rtdst && !memcmp(&(packet->ip6hdr.ip6_dst), &(frags->packet.ip6hdr.ip6_dst), sizeof(struct in6_addr)))
                          || (packet->have_ip6rtdst && !memcmp(&(packet->ip6rtdst), &(frags->packet.ip6hdr.ip6_dst), sizeof(struct in6_addr))))) {

            layer_tracef("release frags %x", packet->ip6frag.ip6f_ident);
            break;
        }
    }

    if (frags) {
        pcap_thread_ext_frag_fragment_t *frag, *f;

        /* Found it, remove from list */
        if (frags_prev) {
            frags_prev->next = frags->next;
        }
        if (ctx->fragments == frags) {
            ctx->fragments = frags->next;
        }
        frags->next = 0;
        ctx->num_fragments--;

        for (f = frags->fragments; f;) {
            frag = f;
            f    = f->next;
            if (frag->payload) {
                free(frag->payload);
            }
            free(frag);
        }

        if (frags->payload) {
            free(frags->payload);
        }
        free(frags);
    }
}
#endif

static pcap_thread_packet_state_t pcap_thread_layer_callback_frag_reassemble(void* _ctx, const pcap_thread_packet_t* packet, const u_char* payload, size_t length, pcap_thread_packet_t** whole_packet, const u_char** whole_payload, size_t* whole_length)
{
    _ctx_t*                    ctx   = (_ctx_t*)_ctx;
    pcap_thread_packet_state_t state = PCAP_THREAD_PACKET_INVALID;

    if (!ctx) {
        return PCAP_THREAD_PACKET_INVALID;
    }
    if (!packet) {
        return PCAP_THREAD_PACKET_INVALID;
    }
    if (!payload) {
        return PCAP_THREAD_PACKET_INVALID;
    }
    if (!length) {
        return PCAP_THREAD_PACKET_INVALID;
    }
    if (!whole_packet) {
        return PCAP_THREAD_PACKET_INVALID;
    }
    if (!whole_payload) {
        return PCAP_THREAD_PACKET_INVALID;
    }
    if (!whole_length) {
        return PCAP_THREAD_PACKET_INVALID;
    }

    if (ctx && packet && payload && length
        && whole_packet && whole_payload && whole_length) {
        if (packet->have_iphdr) {
#ifdef HAVE_PTHREAD
            if (pthread_mutex_lock(&(ctx->mutex))) {
                return PCAP_THREAD_PACKET_EMUTEX;
            }
#endif
            state = reassemble_ipv4(ctx, packet, payload, length, whole_packet, whole_payload, whole_length);
#ifdef HAVE_PTHREAD
            if (pthread_mutex_unlock(&(ctx->mutex))) {
                if (state == PCAP_THREAD_PACKET_OK && *whole_packet && *whole_payload && *whole_length) {
                    _release(ctx, *whole_packet);
                }
                return PCAP_THREAD_PACKET_EMUTEX;
            }
#endif
        } else if (packet->have_ip6hdr && packet->have_ip6frag) {
#ifdef HAVE_PTHREAD
            if (pthread_mutex_lock(&(ctx->mutex))) {
                return PCAP_THREAD_PACKET_EMUTEX;
            }
#endif
            state = reassemble_ipv6(ctx, packet, payload, length, whole_packet, whole_payload, whole_length);
#ifdef HAVE_PTHREAD
            if (pthread_mutex_unlock(&(ctx->mutex))) {
                if (state == PCAP_THREAD_PACKET_OK && *whole_packet && *whole_payload && *whole_length) {
                    _release(ctx, *whole_packet);
                }
                return PCAP_THREAD_PACKET_EMUTEX;
            }
#endif
        }
    }

    return state;
}

static void pcap_thread_layer_callback_frag_release(void* _ctx, const pcap_thread_packet_t* packet, const u_char* payload, size_t length)
{
    _ctx_t*                           ctx = (_ctx_t*)_ctx;
    pcap_thread_ext_frag_fragments_t *frags, *frags_prev;

    if (!ctx) {
        return;
    }
    if (!packet) {
        return;
    }
    if (packet->have_ip6hdr) {
        if (!packet->have_ip6frag) {
            return;
        }
    } else if (!packet->have_iphdr) {
        return;
    }

#ifdef HAVE_PTHREAD
    if (pthread_mutex_lock(&(ctx->mutex))) {
        return;
    }
#endif

    /* Find packet fragments */
    for (frags_prev = 0, frags = ctx->fragments; frags; frags_prev = frags, frags = frags->next) {
        if ((frags->packet.have_iphdr
                && packet->iphdr.ip_id == frags->packet.iphdr.ip_id
                && packet->iphdr.ip_p == frags->packet.iphdr.ip_p
                && packet->iphdr.ip_src.s_addr == frags->packet.iphdr.ip_src.s_addr
                && packet->iphdr.ip_dst.s_addr == frags->packet.iphdr.ip_dst.s_addr)
            || (frags->packet.have_ip6hdr
                   && packet->ip6frag.ip6f_ident == frags->packet.ip6frag.ip6f_ident
                   && !memcmp(&(packet->ip6hdr.ip6_src), &(frags->packet.ip6hdr.ip6_src), sizeof(struct in6_addr))
                   && ((!packet->have_ip6rtdst && !memcmp(&(packet->ip6hdr.ip6_dst), &(frags->packet.ip6hdr.ip6_dst), sizeof(struct in6_addr)))
                          || (packet->have_ip6rtdst && !memcmp(&(packet->ip6rtdst), &(frags->packet.ip6hdr.ip6_dst), sizeof(struct in6_addr)))))) {

            /* Found it, remove from list */
            if (frags_prev) {
                frags_prev->next = frags->next;
            }
            if (ctx->fragments == frags) {
                ctx->fragments = frags->next;
            }
            frags->next = 0;
            ctx->num_fragments--;
            break;
        }
    }

#ifdef HAVE_PTHREAD
    pthread_mutex_unlock(&(ctx->mutex));
#endif

    if (frags) {
        pcap_thread_ext_frag_fragment_t *frag, *f;

        for (f = frags->fragments; f;) {
            frag = f;
            f    = f->next;
            if (frag->payload) {
                free(frag->payload);
            }
            free(frag);
        }

        if (frags->payload) {
            free(frags->payload);
        }
        free(frags);
    }
}
