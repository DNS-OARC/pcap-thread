# Author Jerry Lundström <jerry@dns-oarc.net>
# Copyright (c) 2016-2025 OARC, Inc.
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

ACLOCAL_AMFLAGS = -I ../m4

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in $(srcdir)/config.h.in
CLEANFILES = pcap_thread.c pcap_thread.h \
    pcap_thread_ext_frag.c pcap_thread_ext_frag.h

SUBDIRS = test

AM_CFLAGS = -Wall -I$(srcdir) -I$(top_srcdir)/../ $(PTHREAD_CFLAGS)

bin_PROGRAMS    = hexdump

hexdump_SOURCES = hexdump.c pcap_thread.c pcap_thread_ext_frag.c
hexdump_LDADD   = $(PTHREAD_LIBS)

pcap_thread.c: $(top_srcdir)/../pcap_thread.c pcap_thread.h
	cp "$(top_srcdir)/../pcap_thread.c" .

pcap_thread.h: $(top_srcdir)/../pcap_thread.h
	cp "$(top_srcdir)/../pcap_thread.h" .

pcap_thread_ext_frag.c: $(top_srcdir)/../pcap_thread_ext_frag.c pcap_thread_ext_frag.h
	cp "$(top_srcdir)/../pcap_thread_ext_frag.c" .

pcap_thread_ext_frag.h: $(top_srcdir)/../pcap_thread_ext_frag.h pcap_thread.h
	cp "$(top_srcdir)/../pcap_thread_ext_frag.h" .

test: check
