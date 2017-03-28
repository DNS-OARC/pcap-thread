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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

void layer(u_char* user, const pcap_thread_packet_t* packet, const u_char* payload, size_t length) {
    const pcap_thread_packet_t* first = packet;
    size_t n;

    while (first->have_prevpkt) {
        first = first->prevpkt;
    }

    if (user) {
        printf("name:%s ts:%ld.%ld caplen:%d len:%d datalink:%s data:",
            first->name,
            (long)first->pkthdr.ts.tv_sec, first->pkthdr.ts.tv_usec,
            first->pkthdr.caplen,
            first->pkthdr.len,
            pcap_datalink_val_to_name(first->dlt)
        );
    }
    else {
        printf("%s ", first->name);
    }
    for (n = 0; n < length; n++) {
        printf("%02x", payload[n]);
    }
    printf("\n");
}

void invalid(u_char* user, const pcap_thread_packet_t* packet, const u_char* payload, size_t length) {
    const pcap_thread_packet_t* first = packet;
    size_t n;

    while (first->have_prevpkt) {
        first = first->prevpkt;
    }

    if (user) {
        printf("%s name:%s ts:%ld.%ld caplen:%d len:%d datalink:%s data:",
            packet->state == PCAP_THREAD_PACKET_UNSUPPORTED ? "unsupported" : "invalid",
            first->name,
            (long)first->pkthdr.ts.tv_sec, first->pkthdr.ts.tv_usec,
            first->pkthdr.caplen,
            first->pkthdr.len,
            pcap_datalink_val_to_name(first->dlt)
        );
    }
    else {
        printf("%c%s ",
            packet->state == PCAP_THREAD_PACKET_UNSUPPORTED ? '?' : '-',
            first->name
        );
    }
    for (n = 0; n < length; n++) {
        printf("%02x", payload[n]);
    }
    printf("\n");
}

void callback(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* pkt, const char* name, int dlt) {
    bpf_u_int32 i;

    if (user) {
        printf("name:%s ts:%ld.%ld caplen:%d len:%d datalink:%s data:",
            name,
            (long)pkthdr->ts.tv_sec, pkthdr->ts.tv_usec,
            pkthdr->caplen,
            pkthdr->len,
            pcap_datalink_val_to_name(dlt)
        );
    }
    else {
        printf("%s ", name);
    }
    for (i = 0; i < pkthdr->caplen; i++) {
        printf("%02x", pkt[i]);
    }
    printf("\n");
}

void dropback(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* pkt, const char* name, int dlt) {
    bpf_u_int32 i;

    if (user) {
        printf("dropped name:%s ts:%ld.%ld caplen:%d len:%d datalink:%s data:",
            name,
            (long)pkthdr->ts.tv_sec, pkthdr->ts.tv_usec,
            pkthdr->caplen,
            pkthdr->len,
            pcap_datalink_val_to_name(dlt)
        );
    }
    else {
        printf("!%s ", name);
    }
    for (i = 0; i < pkthdr->caplen; i++) {
        printf("%02x", pkt[i]);
    }
    printf("\n");
}

void stat_callback(u_char* user, const struct pcap_stat* stats, const char* name, int dlt) {
    if (user) {
        printf("stats name:%s datalink:%s received:%u dropped:%u ifdropped:%u\n",
            name,
            pcap_datalink_val_to_name(dlt),
            stats->ps_recv,
            stats->ps_drop,
            stats->ps_ifdrop
        );
    }
    else {
        printf("+%s %u %u %u\n", name, stats->ps_recv, stats->ps_drop, stats->ps_ifdrop);
    }
}

pcap_thread_t pt = PCAP_THREAD_T_INIT;
pcap_thread_pcaplist_t __pcaplist_not_used = PCAP_THREAD_PCAPLIST_T_INIT;

void stop(int signum) {
    pcap_thread_stop(&pt);
}

#define MAX_INTERFACES 64
#define MAX_FILTER_SIZE 64*1024

int do_next(int cnt) {
    int ret;

    while (cnt--) {
        if ((ret = pcap_thread_next(&pt))) {
            return ret;
        }
    }
    return PCAP_THREAD_OK;
}

int main(int argc, char** argv) {
    int opt, err = 0, ret = 0, interface = 0, verbose = 0, i, stats = 0, cnt = 0, layers = 0;
    char* interfaces[MAX_INTERFACES];
    char is_file[MAX_INTERFACES];
    char filter[MAX_FILTER_SIZE];
    char* filterp = filter;
    size_t filter_left = MAX_FILTER_SIZE;
    struct sigaction sa;
    time_t exit_after_time = 0;

    memset(is_file, 0, MAX_INTERFACES);
    memset(&sa, 0, sizeof(struct sigaction));

    sa.sa_handler = stop;
    sigfillset(&sa.sa_mask);
    if ((ret = sigaction(SIGINT, &sa, 0))) {
        fprintf(stderr, "sigaction(SIGINT) error %d: %s\n", errno, strerror(errno));
        exit(4);
    }
    if ((ret = sigaction(SIGHUP, &sa, 0))) {
        fprintf(stderr, "sigaction(SIGHUP) error %d: %s\n", errno, strerror(errno));
        exit(4);
    }

    while ((opt = getopt(argc, argv, "T:M:C:s:p:m:t:b:I:d:o:n:S:i:W:a:vr:H:P:hDVA:c:L:")) != -1) {
        switch (opt) {
        case 'T':
            ret = pcap_thread_set_use_threads(&pt, atoi(optarg) ? 1 : 0);
            break;
        case 'M':
            if (!strcmp("cond", optarg))
                ret = pcap_thread_set_queue_mode(&pt, PCAP_THREAD_QUEUE_MODE_COND);
            else if (!strcmp("wait", optarg))
                ret = pcap_thread_set_queue_mode(&pt, PCAP_THREAD_QUEUE_MODE_WAIT);
            else if (!strcmp("yield", optarg))
                ret = pcap_thread_set_queue_mode(&pt, PCAP_THREAD_QUEUE_MODE_YIELD);
            else if (!strcmp("direct", optarg))
                ret = pcap_thread_set_queue_mode(&pt, PCAP_THREAD_QUEUE_MODE_DIRECT);
            else
                err = -1;
            break;
        case 'C':
            if (!strcmp("cond", optarg))
                ret = pcap_thread_set_callback_queue_mode(&pt, PCAP_THREAD_QUEUE_MODE_COND);
            else if (!strcmp("drop", optarg))
                ret = pcap_thread_set_callback_queue_mode(&pt, PCAP_THREAD_QUEUE_MODE_DROP);
            else if (!strcmp("wait", optarg))
                ret = pcap_thread_set_callback_queue_mode(&pt, PCAP_THREAD_QUEUE_MODE_WAIT);
            else if (!strcmp("yield", optarg))
                ret = pcap_thread_set_callback_queue_mode(&pt, PCAP_THREAD_QUEUE_MODE_YIELD);
            else
                err = -1;
            break;
        case 's':
            ret = pcap_thread_set_snaplen(&pt, atoi(optarg));
            break;
        case 'p':
            ret = pcap_thread_set_promiscuous(&pt, atoi(optarg) ? 1 : 0);
            break;
        case 'm':
            ret = pcap_thread_set_monitor(&pt, atoi(optarg) ? 1 : 0);
            break;
        case 't':
            ret = pcap_thread_set_timeout(&pt, atoi(optarg));
            break;
        case 'b':
            ret = pcap_thread_set_buffer_size(&pt, atoi(optarg));
            break;
        case 'I':
            ret = pcap_thread_set_immediate_mode(&pt, atoi(optarg) ? 1 : 0);
            break;
        case 'd':
            if (!strcmp("in", optarg))
                ret = pcap_thread_set_direction(&pt, PCAP_D_IN);
            else if (!strcmp("out", optarg))
                ret = pcap_thread_set_direction(&pt, PCAP_D_OUT);
            else if (!strcmp("inout", optarg))
                ret = pcap_thread_set_direction(&pt, PCAP_D_INOUT);
            else
                err = -1;
            break;
        case 'o':
            ret = pcap_thread_set_filter_optimize(&pt, atoi(optarg) ? 1 : 0);
            break;
        case 'n':
            {
                unsigned int netmask[4] = { 0, 0, 0, 0};
                if (sscanf(optarg, "%u.%u.%u.%u", &netmask[0], &netmask[1], &netmask[2], &netmask[3]) == 4
                    && netmask[0] < 256
                    && netmask[1] < 256
                    && netmask[2] < 256
                    && netmask[3] < 256)
                {
                    /* TODO: Is this correct? */
                    bpf_u_int32 n = ((netmask[0] & 0xff) << 24)
                        + ((netmask[1] & 0xff) << 16)
                        + ((netmask[2] & 0xff) << 8)
                        + (netmask[3] & 0xff);
                    ret = pcap_thread_set_filter_netmask(&pt, n);
                }
                else
                    err = -1;
            }
            break;
        case 'S':
            ret = pcap_thread_set_queue_size(&pt, atoi(optarg));
            break;
        case 'i':
            if (interface != MAX_INTERFACES)
                interfaces[interface++] = strdup(optarg);
            else
                err = -1;
            break;
        case 'r':
            if (interface != MAX_INTERFACES) {
                is_file[interface] = 1;
                interfaces[interface++] = strdup(optarg);
            }
            else
                err = -1;
            break;
        case 'W':
            {
                struct timeval t = { 0, 0 };

                t.tv_sec = atoi(optarg) / 1000000;
                t.tv_usec = atoi(optarg) % 1000000;

                ret = pcap_thread_set_queue_wait(&pt, t);
            }
            break;
        case 'a':
            if (atoi(optarg))
                pcap_thread_set_activate_mode(&pt, PCAP_THREAD_ACTIVATE_MODE_DELAYED);
            break;
        case 'v':
            verbose = 1;
            break;
        case 'H':
#ifdef HAVE_PCAP_SET_TSTAMP_TYPE
            if (!strcmp("host", optarg))
                ret = pcap_thread_set_timestamp_type(&pt, PCAP_TSTAMP_HOST);
            else if (!strcmp("host_lowprec", optarg))
                ret = pcap_thread_set_timestamp_type(&pt, PCAP_TSTAMP_HOST_LOWPREC);
            else if (!strcmp("host_hiprec", optarg))
                ret = pcap_thread_set_timestamp_type(&pt, PCAP_TSTAMP_HOST_HIPREC);
            else if (!strcmp("adapter", optarg))
                ret = pcap_thread_set_timestamp_type(&pt, PCAP_TSTAMP_ADAPTER);
            else if (!strcmp("adapter_unsynced", optarg))
                ret = pcap_thread_set_timestamp_type(&pt, PCAP_TSTAMP_ADAPTER_UNSYNCED);
            else
                err = -1;
#else
            err = -2;
#endif
            break;
        case 'P':
#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
            if (!strcmp("micro", optarg))
                ret = pcap_thread_set_timestamp_precision(&pt, PCAP_TSTAMP_PRECISION_MICRO);
            else if (!strcmp("nano", optarg))
                ret = pcap_thread_set_timestamp_type(&pt, PCAP_TSTAMP_PRECISION_NANO);
            else
                err = -1;
#else
            err = -2;
#endif
            break;
        case 'h':
            printf(
"usage: hexdump [options] [filter]\n"
" -A <secs>          exit after a number of seconds\n"
" -c <count>         process count packets then exit\n"
" -T <1|0>           use/not use threads\n"
" -M <mode>          queue mode: cond, wait or yield\n"
" -C <mode>          callback queue mode: cond, drop, wait, yield or direct\n"
" -s <len>           snap length\n"
" -p <1|0>           use/not use promiscuous mode\n"
" -m <1|0>           use/not use monitor mode\n"
" -t <ms>            timeout\n"
" -b <bytes>         buffer size\n"
" -I <1|0>           use/not use immediate mode\n"
" -d <dir>           direction: in, out or inout\n"
" -o <1|0>           use/not use filter optimization\n"
" -n <mask>          filter netmask\n"
" -S <size>          queue size\n"
" -i <name>          interface (multiple)\n"
" -r <file>          pcap savefile (multiple)\n"
" -W <usec>          queue wait\n"
" -a <1|0>           use/not use delayed activation of interface capturing\n"
" -v                 verbose\n"
#ifdef HAVE_PCAP_SET_TSTAMP_TYPE
" -H <type>          timestamp type: host, host_lowprec, host_hiprec, adapter\n"
"                    or adapter_unsynced\n"
#endif
#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
" -P <type>          timestamp precision: micro or nano\n"
#endif
" -L <layer>         capture at layer: ether, null, loop, ieee802, gre, ip,\n"
"                                      ipv4, ipv6, udp or tcp\n"
" -D                 display stats on exit\n"
" -V                 display version and exit\n"
" -h                 this\n"
            );
            exit(0);
        case 'D':
            stats = 1;
            break;
        case 'V':
            printf("hexdump version %s (pcap_thread version %s)\n",
                PACKAGE_VERSION,
                PCAP_THREAD_VERSION_STR
            );
            exit(0);
        case 'A':
            exit_after_time = atoi(optarg);
            break;
        case 'c':
            cnt = atoi(optarg);
            break;
        case 'L':
            if (!strcmp("ether", optarg))
                ret = pcap_thread_set_callback_ether(&pt, &layer);
            else if (!strcmp("null", optarg))
                ret = pcap_thread_set_callback_null(&pt, &layer);
            else if (!strcmp("loop", optarg))
                ret = pcap_thread_set_callback_loop(&pt, &layer);
            else if (!strcmp("ieee802", optarg))
                ret = pcap_thread_set_callback_ieee802(&pt, &layer);
            else if (!strcmp("gre", optarg))
                ret = pcap_thread_set_callback_gre(&pt, &layer);
            else if (!strcmp("ip", optarg))
                ret = pcap_thread_set_callback_ip(&pt, &layer);
            else if (!strcmp("ipv4", optarg))
                ret = pcap_thread_set_callback_ipv4(&pt, &layer);
            else if (!strcmp("ipv6", optarg))
                ret = pcap_thread_set_callback_ipv6(&pt, &layer);
            else if (!strcmp("udp", optarg))
                ret = pcap_thread_set_callback_udp(&pt, &layer);
            else if (!strcmp("tcp", optarg))
                ret = pcap_thread_set_callback_tcp(&pt, &layer);
            else
                err = -1;

            if (ret == PCAP_THREAD_OK)
                ret = pcap_thread_set_use_layers(&pt, 1);

            layers = 1;
            break;
        default:
            err = -1;
        }
    }

    if (err == -2) {
        fprintf(stderr, "Unsupported argument(s)\n");
        exit(1);
    }
    if (err == -1) {
        fprintf(stderr, "Invalid argument(s)\n");
        exit(1);
    }
    if (ret == PCAP_THREAD_EPCAP) {
        fprintf(stderr, "pcap error [%d]: %s (%s)\n", pcap_thread_status(&pt), pcap_statustostr(pcap_thread_status(&pt)), pcap_thread_errbuf(&pt));
        exit(2);
    }
    if (ret == PCAP_THREAD_ERRNO) {
        fprintf(stderr, "system error [%d]: %s (%s)\n", errno, strerror(errno), pcap_thread_errbuf(&pt));
        exit(2);
    }
    if (ret) {
        fprintf(stderr, "pcap_thread error [%d]: %s\n", ret, pcap_thread_strerr(ret));
        exit(2);
    }

    memset(filter, 0, MAX_FILTER_SIZE);
    while (optind < argc) {
        size_t len = strlen(argv[optind]);

        if ((len + 1) > filter_left) {
            fprintf(stderr, "Filter too long\n");
            exit(3);
        }
        if (filter_left != MAX_FILTER_SIZE) {
            strncat(filterp, " ", 1);
            filterp++;
            filter_left--;
        }
        strncat(filterp, argv[optind++], len);
        filterp += len;
        filter_left -= len;
    }

    if (verbose) {
        printf("use_threads: %s\n", pcap_thread_use_threads(&pt) ? "yes" : "no");
        printf("queue_mode: ");
        switch (pcap_thread_queue_mode(&pt)) {
            case PCAP_THREAD_QUEUE_MODE_COND:
                printf("cond\n");
                break;
            case PCAP_THREAD_QUEUE_MODE_WAIT:
                printf("wait\n");
                break;
            case PCAP_THREAD_QUEUE_MODE_YIELD:
                printf("yield\n");
                break;
            default:
                printf("unknown\n");
        }
        printf("queue_wait: ");
        {
            struct timeval t = pcap_thread_queue_wait(&pt);
            printf("%ld.%ld\n", (long)t.tv_sec, t.tv_usec);
        }
        printf("queue_size: %lu\n", pcap_thread_queue_size(&pt));
        printf("snaplen: %d\n", pcap_thread_snaplen(&pt));
        printf("promiscuous: %s\n", pcap_thread_promiscuous(&pt) ? "yes" : "no");
        printf("monitor: %s\n", pcap_thread_monitor(&pt) ? "yes" : "no");
        printf("timeout: %d\n", pcap_thread_timeout(&pt));
        printf("buffer_size: %d\n", pcap_thread_buffer_size(&pt));
        printf("immediate_mode: %s\n", pcap_thread_immediate_mode(&pt) ? "yes" : "no");
        printf("direction: ");
        switch (pcap_thread_direction(&pt)) {
            case PCAP_D_IN:
                printf("in\n");
                break;
            case PCAP_D_OUT:
                printf("out\n");
                break;
            case PCAP_D_INOUT:
                printf("inout\n");
                break;
            default:
                printf("unknown\n");
        }
        printf("filter_optimize: %s\n", pcap_thread_filter_optimze(&pt) ? "yes" : "no");
        printf("filter_netmask: 0x%x\n", pcap_thread_filter_netmask(&pt));
        printf("filter: %s\n", filter);
    }

    if (exit_after_time) {
        struct timeval tv = { 0, 0 };

        tv.tv_sec = exit_after_time;
        pcap_thread_set_timedrun(&pt, tv);
    }

    if (filterp != filter && (ret = pcap_thread_set_filter(&pt, filter, filterp - filter)))
        fprintf(stderr, "filter ");
    else if (!layers && (ret = pcap_thread_set_callback(&pt, callback)))
        fprintf(stderr, "set callback ");
    else if ((ret = pcap_thread_set_dropback(&pt, dropback)))
        fprintf(stderr, "set dropback ");
    else if (layers && (ret = pcap_thread_set_callback_invalid(&pt, invalid)))
        fprintf(stderr, "set invalid callback ");
    else {
        for(i = 0; i < interface; i++) {
            if (is_file[i]) {
                if (verbose) printf("file: %s\n", interfaces[i]);
                if ((ret = pcap_thread_open_offline(&pt, interfaces[i], verbose ? (u_char*)1 : 0))) {
                    fprintf(stderr, "file:%s ", interfaces[i]);
                    break;
                }
                if (pcap_thread_filter_errno(&pt)) {
                    printf("non-fatal filter errno [%d]: %s\n", pcap_thread_filter_errno(&pt), strerror(pcap_thread_filter_errno(&pt)));
                }
            }
            else {
                if (verbose) printf("interface: %s\n", interfaces[i]);
                if ((ret = pcap_thread_open(&pt, interfaces[i], verbose ? (u_char*)1 : 0))) {
                    fprintf(stderr, "interface:%s ", interfaces[i]);
                    break;
                }
                if (pcap_thread_filter_errno(&pt)) {
                    printf("non-fatal filter errno [%d]: %s\n", pcap_thread_filter_errno(&pt), strerror(pcap_thread_filter_errno(&pt)));
                }
            }
        }
        if (verbose) {
            printf("snapshot: %d\n", pcap_thread_snapshot(&pt));
        }

        if (ret)
            fprintf(stderr, "open ");
        else if (cnt && (ret = do_next(cnt)))
            fprintf(stderr, "next ");
        else if (!cnt && pcap_thread_activate_mode(&pt) == PCAP_THREAD_ACTIVATE_MODE_DELAYED && (ret = pcap_thread_activate(&pt)))
            fprintf(stderr, "activate ");
        else if (!cnt && (ret = pcap_thread_run(&pt)))
            fprintf(stderr, "run ");
        else if (stats && (ret = pcap_thread_stats(&pt, stat_callback, verbose ? (u_char*)1 : 0)))
            fprintf(stderr, "stats ");
        else if (!ret && (ret = pcap_thread_close(&pt)))
            fprintf(stderr, "close ");

        if (pcap_thread_activate_mode(&pt) == PCAP_THREAD_ACTIVATE_MODE_DELAYED && pcap_thread_filter_errno(&pt)) {
            printf("non-fatal filter errno [%d]: %s\n", pcap_thread_filter_errno(&pt), strerror(pcap_thread_filter_errno(&pt)));
        }
    }

    if (ret == PCAP_THREAD_EPCAP) {
        fprintf(stderr, "pcap error [%d]: %s (%s)\n", pcap_thread_status(&pt), pcap_statustostr(pcap_thread_status(&pt)), pcap_thread_errbuf(&pt));
        exit(2);
    }
    if (ret == PCAP_THREAD_ERRNO) {
        fprintf(stderr, "system error [%d]: %s (%s)\n", errno, strerror(errno), pcap_thread_errbuf(&pt));
        exit(2);
    }
    if (ret) {
        fprintf(stderr, "pcap_thread error [%d]: %s\n", ret, pcap_thread_strerr(ret));
        exit(2);
    }

    return 0;
}
