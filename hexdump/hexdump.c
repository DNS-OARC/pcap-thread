#include "config.h"
#include "pcap_thread.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void callback(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* pkt, int dlt) {
    bpf_u_int32 i;

    if (user) {
        printf("ts:%lu.%lu caplen:%d len:%d datalink:%s data:",
            pkthdr->ts.tv_sec, pkthdr->ts.tv_usec,
            pkthdr->caplen,
            pkthdr->len,
            pcap_datalink_val_to_name(dlt)
        );
    }
    for (i = 0; i < pkthdr->caplen; i++) {
        printf("%02x", pkt[i]);
    }
    printf("\n");
}

void dropback(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* pkt, int dlt) {
    bpf_u_int32 i;

    if (user) {
        printf("dropped ts:%lu.%lu caplen:%d len:%d datalink:%s data:",
            pkthdr->ts.tv_sec, pkthdr->ts.tv_usec,
            pkthdr->caplen,
            pkthdr->len,
            pcap_datalink_val_to_name(dlt)
        );
    }
    else {
        printf("!");
    }
    for (i = 0; i < pkthdr->caplen; i++) {
        printf("%02x", pkt[i]);
    }
    printf("\n");
}

#define MAX_INTERFACES 64
#define MAX_FILTER_SIZE 4096

int main(int argc, char** argv) {
    pcap_thread_t pt = PCAP_THREAD_T_INIT;
    int flags, opt, err = 0, interface = 0, verbose = 0, i;
    char* interfaces[MAX_INTERFACES];
    char is_file[MAX_INTERFACES];
    char filter[MAX_FILTER_SIZE];
    char* filterp = filter;
    size_t filter_left = MAX_FILTER_SIZE;

    memset(is_file, 0, MAX_INTERFACES);

    while ((opt = getopt(argc, argv, "T:M:s:p:m:t:b:I:d:o:n:S:i:W:vr:H:P:h")) != -1) {
        switch (opt) {
        case 'T':
            err = pcap_thread_set_use_threads(&pt, atoi(optarg) ? 1 : 0);
            break;
        case 'M':
            if (!strcmp("cond", optarg))
                err = pcap_thread_set_queue_mode(&pt, PCAP_THREAD_QUEUE_MODE_COND);
            else if (!strcmp("wait", optarg))
                err = pcap_thread_set_queue_mode(&pt, PCAP_THREAD_QUEUE_MODE_WAIT);
            else if (!strcmp("yield", optarg))
                err = pcap_thread_set_queue_mode(&pt, PCAP_THREAD_QUEUE_MODE_YIELD);
            else
                err = -1;
            break;
        case 's':
            err = pcap_thread_set_snaplen(&pt, atoi(optarg));
            break;
        case 'p':
            err = pcap_thread_set_promiscuous(&pt, atoi(optarg) ? 1 : 0);
            break;
        case 'm':
            err = pcap_thread_set_monitor(&pt, atoi(optarg) ? 1 : 0);
            break;
        case 't':
            err = pcap_thread_set_timeout(&pt, atoi(optarg));
            break;
        case 'b':
            err = pcap_thread_set_buffer_size(&pt, atoi(optarg));
            break;
        case 'I':
            err = pcap_thread_set_immediate_mode(&pt, atoi(optarg) ? 1 : 0);
            break;
        case 'd':
            if (!strcmp("in", optarg))
                err = pcap_thread_set_direction(&pt, PCAP_D_IN);
            else if (!strcmp("out", optarg))
                err = pcap_thread_set_direction(&pt, PCAP_D_OUT);
            else if (!strcmp("inout", optarg))
                err = pcap_thread_set_direction(&pt, PCAP_D_INOUT);
            else
                err = -1;
            break;
        case 'o':
            err = pcap_thread_set_filter_optimize(&pt, atoi(optarg) ? 1 : 0);
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
                    err = pcap_thread_set_filter_netmask(&pt, n);
                }
                else
                    err = -1;
            }
            break;
        case 'S':
            err = pcap_thread_set_queue_size(&pt, atoi(optarg));
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

                err = pcap_thread_set_queue_wait(&pt, t);
            }
            break;
        case 'v':
            verbose = 1;
            break;
        case 'H':
#ifdef HAVE_PCAP_SET_TSTAMP_TYPE
            if (!strcmp("host", optarg))
                err = pcap_thread_set_timestamp_type(&pt, PCAP_TSTAMP_HOST);
            else if (!strcmp("host_lowprec", optarg))
                err = pcap_thread_set_timestamp_type(&pt, PCAP_TSTAMP_HOST_LOWPREC);
            else if (!strcmp("host_hiprec", optarg))
                err = pcap_thread_set_timestamp_type(&pt, PCAP_TSTAMP_HOST_HIPREC);
            else if (!strcmp("adapter", optarg))
                err = pcap_thread_set_timestamp_type(&pt, PCAP_TSTAMP_ADAPTER);
            else if (!strcmp("adapter_unsynced", optarg))
                err = pcap_thread_set_timestamp_type(&pt, PCAP_TSTAMP_ADAPTER_UNSYNCED);
            else
                err = -1;
#else
            err = -2;
#endif
            break;
        case 'P':
#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
            if (!strcmp("micro", optarg))
                err = pcap_thread_set_timestamp_precision(&pt, PCAP_TSTAMP_PRECISION_MICRO);
            else if (!strcmp("nano", optarg))
                err = pcap_thread_set_timestamp_type(&pt, PCAP_TSTAMP_PRECISION_NANO);
            else
                err = -1;
#else
            err = -2;
#endif
            break;
        case 'h':
            printf(
"usage: hexdump [options] [filter]\n"
" -T <0|1>           use/not use threads\n"
" -M <mode>          queue mode: cond, wait or yield\n"
" -s <len>           snap length\n"
" -p <0|1>           use/not use promiscuous mode\n"
" -m <0|1>           use/not use monitor mode\n"
" -t <ms>            timeout\n"
" -b <bytes>         buffer size\n"
" -I <0|1>           use/not use immediate mode\n"
" -d <dir>           direction: in, out or inout\n"
" -o <0|1>           use/not use filter optimization\n"
" -n <mask>          filter netmask\n"
" -S <size>          queue size\n"
" -i <name>          interface (multiple)\n"
" -r <file>          pcap savefile (multiple)\n"
" -W <usec>          queue wait\n"
" -v                 verbose\n"
" -H <type>          timestamp type: host, host_lowprec, host_hiprec, adapter\n"
"                    or adapter_unsynced\n"
" -P <type>          timestamp precision: micro or nano\n"
" -h                 this\n"
            );
            exit(0);
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
    if (err) {
        fprintf(stderr, "pcap_thread error [%d:%d]: %s\n", err, pcap_thread_status(&pt), pcap_thread_errbuf(&pt));
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
            printf("%lu.%lu\n", t.tv_sec, t.tv_usec);
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

    if (filterp != filter && (err = pcap_thread_set_filter(&pt, filter, filterp - filter)))
        fprintf(stderr, "filter ");
    else if ((err = pcap_thread_set_callback(&pt, callback)))
        fprintf(stderr, "set callback ");
    else if ((err = pcap_thread_set_dropback(&pt, dropback)))
        fprintf(stderr, "set dropback ");
    else {
        for(i = 0; i < interface; i++) {
            if (is_file[i]) {
                if (verbose) printf("file: %s\n", interfaces[i]);
                if ((err = pcap_thread_open_offline(&pt, interfaces[i], verbose ? (u_char*)1 : 0)))
                    break;
            }
            else {
                if (verbose) printf("interface: %s\n", interfaces[i]);
                if ((err = pcap_thread_open(&pt, interfaces[i], verbose ? (u_char*)1 : 0)))
                    break;
            }
        }
        if (verbose) {
            printf("snapshot: %d\n", pcap_thread_snapshot(&pt));
        }

        if (err)
            fprintf(stderr, "interface ");
        else if ((err = pcap_thread_run(&pt)))
            fprintf(stderr, "run ");
        else if ((err = pcap_thread_close(&pt)))
            fprintf(stderr, "close ");
    }

    if (err) {
        fprintf(stderr, "pcap_thread error [%d:%d]: %s\n", err, pcap_thread_status(&pt), pcap_thread_errbuf(&pt));
        exit(2);
    }

    return 0;
}
