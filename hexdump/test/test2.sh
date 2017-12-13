#!/bin/sh -xe
# Author Jerry Lundström <jerry@dns-oarc.net>
# Copyright (c) 2017, OARC, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived
#    from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

rm -f test2.out

for file in v4_frag_dup_udp.pcap-dist v4_frag_empty_udp.pcap-dist \
    v4_frag_nomf_udp.pcap-dist v4_frag_offset_offbyone1_udp.pcap-dist \
    v4_frag_offset_offbyone2_udp.pcap-dist v4_frag_order_udp.pcap-dist \
    v4_frag_skip_first_udp.pcap-dist v4_frag_skip_last_udp.pcap-dist \
    v4_frag_skip_middle_udp.pcap-dist; do
        ../hexdump -F 4 -F R4 -F p4100 -L udp -v -r "$file" >>test2.out
done

for file in v4_frag_dup_udp.pcap-dist v4_frag_empty_udp.pcap-dist \
    v4_frag_nomf_udp.pcap-dist v4_frag_offset_offbyone1_udp.pcap-dist \
    v4_frag_offset_offbyone2_udp.pcap-dist v4_frag_order_udp.pcap-dist \
    v4_frag_skip_first_udp.pcap-dist v4_frag_skip_last_udp.pcap-dist \
    v4_frag_skip_middle_udp.pcap-dist; do
        ../hexdump -L udp -v -r "$file" >>test2.out
done

for file in v4_frag_dup_tcp.pcap-dist v4_frag_empty_tcp.pcap-dist \
    v4_frag_nomf_tcp.pcap-dist v4_frag_offset_offbyone1_tcp.pcap-dist \
    v4_frag_offset_offbyone2_tcp.pcap-dist v4_frag_order_tcp.pcap-dist \
    v4_frag_skip_first_tcp.pcap-dist v4_frag_skip_last_tcp.pcap-dist \
    v4_frag_skip_middle_tcp.pcap-dist; do
        ../hexdump -F 4 -F R4 -F p4100 -L tcp -v -r "$file" >>test2.out
done

for file in v4_frag_dup_tcp.pcap-dist v4_frag_empty_tcp.pcap-dist \
    v4_frag_nomf_tcp.pcap-dist v4_frag_offset_offbyone1_tcp.pcap-dist \
    v4_frag_offset_offbyone2_tcp.pcap-dist v4_frag_order_tcp.pcap-dist \
    v4_frag_skip_first_tcp.pcap-dist v4_frag_skip_last_tcp.pcap-dist \
    v4_frag_skip_middle_tcp.pcap-dist; do
        ../hexdump -L tcp -v -r "$file" >>test2.out
done

diff test2.out "$srcdir/test2.gold"
