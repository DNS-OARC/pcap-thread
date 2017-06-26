#!/bin/sh

clang-format-3.8 \
    -style="{BasedOnStyle: webkit, IndentWidth: 4, AlignConsecutiveAssignments: true, AlignConsecutiveDeclarations: true}" \
    -i \
    pcap_thread.c \
    pcap_thread.h \
    hexdump/hexdump.c
