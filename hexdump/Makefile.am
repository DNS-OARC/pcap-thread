MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = pcap_thread.c pcap_thread.h

AM_CFLAGS = -I$(srcdir) $(PTHREAD_CFLAGS)

bin_PROGRAMS    = hexdump

hexdump_SOURCES = hexdump.c pcap_thread.c pcap_thread.h
hexdump_LDADD   = $(PTHREAD_LIBS)

hexdump.c: pcap_thread.h

pcap_thread.c: $(top_srcdir)/../pcap_thread.c pcap_thread.h
	cp "$(top_srcdir)/../pcap_thread.c" "$(srcdir)"

pcap_thread.h: $(top_srcdir)/../pcap_thread.h
	cp "$(top_srcdir)/../pcap_thread.h" "$(srcdir)"
