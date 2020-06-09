# pcap-thread

[![Build Status](https://travis-ci.com/DNS-OARC/pcap-thread.svg?branch=develop)](https://travis-ci.com/DNS-OARC/pcap-thread)

PCAP helper library with POSIX threads support and transport layer callbacks

## About

This is a helper library that will initialize the `pcap_t` for you and,
if you have support, launch a thread per `pcap_t` for the collection which
is then feeded back to the main thread using a queue before being passed on
to the callback.

Additional callbacks exists for simplifying the handling of various transport
layers, based on [pcap_layers](https://github.com/wessels/pcap_layers) by
Duane Wessels (The Measurement Factory, Inc.), such as ether, VLAN, IP, IPv4,
IPv6, GRE tunnels, UDP and TCP.

## Usage

Here is a short example how to use this helper, see the hexdump directory
for a more complete example.

```c
#include "config.h"
#include "pcap-thread/pcap_thread.h"

void callback(u_char* user, const struct pcap_pkthdr* packet_header, const u_char* packet, int datalink_type) {
    ...
}

int main(void) {
    pcap_thread_t pt = PCAP_THREAD_T_INIT;

    pcap_thread_set_snaplen(&pt, 65535);
    pcap_thread_set_filter(&pt, "port 80", 7);
    pcap_thread_set_callback(&pt, callback);
    pcap_thread_open(&pt, "eth0", 0);
    pcap_thread_open(&pt, "lo", 0);
    pcap_thread_run(&pt);
    pcap_thread_close(&pt);

    return 0;
}
```

### git submodule

```shell
git submodule init
git submodule add https://github.com/DNS-OARC/pcap-thread.git src/pcap-thread
git submodule update --init --recursive
```

### auto(re)conf

```shell
autoreconf ... --include=src/pcap-thread/m4
```

### configure.ac

```m4
AX_PCAP_THREAD
```

### Top level Makefile.am

```m4
ACLOCAL_AMFLAGS = ... -I src/pcap-thread/m4
```

### Makefile.am

```m4
AM_CFLAGS += $(PTHREAD_CFLAGS)
AM_CPPFLAGS += $(PTHREAD_CFLAGS)
AM_CXXFLAGS += $(PTHREAD_CFLAGS)

program_SOURCES += pcap-thread/pcap-thread.c
dist_program_SOURCES += pcap-thread/pcap-thread.h
program_LDADD += $(PTHREAD_LIBS)
```

## Author(s)

Jerry Lundström <jerry@dns-oarc.net>

## Copyright and license

Copyright (c) 2016-2017, OARC, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in
   the documentation and/or other materials provided with the
   distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived
   from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
