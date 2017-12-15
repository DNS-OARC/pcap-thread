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

workdir="$PWD/bad-packets"

do_test() {
    files=`ls -1 "$workdir/"*.pcap 2>/dev/null`
    if [ -z "$files" ]; then
        echo "No PCAP files generated"
        exit 1
    fi

    for file in $files; do
        ../hexdump -F 4 -F R4 -F p4100 -F 6 -F R6 -F p6100 -L udp -v -r "$file"
    done
}

if [ -d "$srcdir/bad-packets" ]; then
    mkdir -p "$workdir"
    ( cd "$srcdir/bad-packets" && make FRAG_PKT_SIZE=2123 FRAG_SIZE=1255 NUM_PKTS=5 DESTDIR="$workdir" clean fuzz )
    do_test
elif [ -d "$workdir" ]; then
    ( cd "$workdir" && make FRAG_PKT_SIZE=2123 FRAG_SIZE=1255 NUM_PKTS=5 clean fuzz )
    do_test
else
    echo "bad-packets not found, skipping fuzz tests"
fi
