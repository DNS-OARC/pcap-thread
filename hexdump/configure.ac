AC_PREREQ(2.61)
AC_INIT([hexdump], [0.0.1], [admin@dns-oarc.net], [hexdump], [https://github.com/DNS-OARC/pcap-thread/issues])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_CONFIG_SRCDIR([hexdump.c])
AC_CONFIG_HEADER([config.h])

AC_PROG_CC
AM_PROG_CC_C_O

AX_PCAP_THREAD

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
