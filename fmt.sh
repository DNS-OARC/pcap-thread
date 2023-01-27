#!/bin/sh

clang-format \
    -style=file \
    -i \
    pcap_thread*.c \
    pcap_thread*.h \
    hexdump/hexdump.c
