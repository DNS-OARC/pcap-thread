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

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

CLEANFILES = test*.log test*.trs \
    *.pcap-dist \
    dns.out \
    test2.out \
    test4.out \
    test5.out

TESTS = test1.sh test2.sh \
    test3_120_1120.sh test3_120_1240.sh test3_120_1400.sh test3_120_1800.sh \
    test3_120_900.sh test3_1255_2123.sh test3_1255_2345.sh test3_1255_2566.sh \
    test3_1400_2123.sh test3_1400_2345.sh test3_1400_2566.sh \
    test3_1600_2123.sh test3_1600_2345.sh test3_1600_2566.sh test3_34_1120.sh \
    test3_34_1240.sh test3_34_1400.sh test3_34_1800.sh test3_34_900.sh \
    test3_890_1120.sh test3_890_1240.sh test3_890_1400.sh test3_890_1800.sh \
    test3_890_900.sh \
    test4.sh \
    test5.sh

test1.sh: dns.pcap-dist

test2.sh: v4_frag_dup.pcap-dist v4_frag_empty.pcap-dist \
    v4_frag_nomf.pcap-dist v4_frag_offset_offbyone1.pcap-dist \
    v4_frag_offset_offbyone2.pcap-dist v4_frag_order.pcap-dist \
    v4_frag_skip_first.pcap-dist v4_frag_skip_last.pcap-dist \
    v4_frag_skip_middle.pcap-dist

test4.sh: v6_frag_dup.pcap-dist v6_frag_empty.pcap-dist \
    v6_frag_nomf.pcap-dist v6_frag_offset_offbyone1.pcap-dist \
    v6_frag_offset_offbyone2.pcap-dist v6_frag_order.pcap-dist \
    v6_frag_skip_first.pcap-dist v6_frag_skip_last.pcap-dist \
    v6_frag_skip_middle.pcap-dist

test5.sh: icmp_fuzz.pcap-dist icmpv6_fuzz.pcap-dist

.pcap.pcap-dist:
	cp "$<" "$@"

EXTRA_DIST = $(TESTS) \
    dns.gold dns.pcap \
    v4_frag_dup.pcap v4_frag_empty.pcap v4_frag_nomf.pcap \
    v4_frag_offset_offbyone1.pcap v4_frag_offset_offbyone2.pcap \
    v4_frag_order.pcap v4_frag_skip_first.pcap v4_frag_skip_last.pcap \
    v4_frag_skip_middle.pcap \
    test2.gold \
    v6_frag_dup.pcap v6_frag_empty.pcap v6_frag_nomf.pcap \
    v6_frag_offset_offbyone1.pcap v6_frag_offset_offbyone2.pcap \
    v6_frag_order.pcap v6_frag_skip_first.pcap v6_frag_skip_last.pcap \
    v6_frag_skip_middle.pcap \
    test4.gold \
    icmp_fuzz.pcap icmpv6_fuzz.pcap test5.gold
