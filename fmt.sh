#!/bin/sh

clang-format-4.0 \
    -style=file \
    -i \
    pcap_thread*.c \
    pcap_thread*.h \
    hexdump/hexdump.c
