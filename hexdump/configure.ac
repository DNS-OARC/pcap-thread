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

AC_PREREQ([2.69])
AC_INIT([hexdump],[2.1.0],[admin@dns-oarc.net],[hexdump],[https://github.com/DNS-OARC/pcap-thread/issues])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_CONFIG_SRCDIR([hexdump.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([../m4])

AC_PROG_CC
AM_PROG_CC_C_O

# Check --enable-warn-all
AC_ARG_ENABLE([warn-all], [AS_HELP_STRING([--enable-warn-all], [Enable all compiler warnings])], [AX_CFLAGS_WARN_ALL()])

# Check --with-extra-cflags
AC_ARG_WITH([extra-cflags], [AS_HELP_STRING([--with-extra-cflags=CFLAGS], [Add extra CFLAGS])], [
  AC_MSG_NOTICE([appending extra CFLAGS... $withval])
  AS_VAR_APPEND(CFLAGS, [" $withval"])
])

# Check --with-extra-ldflags
AC_ARG_WITH([extra-ldflags], [AS_HELP_STRING([--with-extra-ldflags=CFLAGS], [Add extra LDFLAGS])], [
  AC_MSG_NOTICE([appending extra LDFLAGS... $withval])
  AS_VAR_APPEND(LDFLAGS, [" $withval"])
])

AC_ARG_ENABLE([pthread],
    [AS_HELP_STRING([--disable-pthread],
        [disable the use of pthread])],
    [],
    [enable_pthread=yes])

AS_IF([test "x$enable_pthread" != xno],
    [AX_PCAP_THREAD],
    [AX_PCAP_THREAD_PCAP])

AC_CONFIG_FILES([Makefile test/Makefile])
AC_OUTPUT
