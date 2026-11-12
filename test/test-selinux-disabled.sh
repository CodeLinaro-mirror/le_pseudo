#!/bin/sh
#
# SPDX-License-Identifier: LGPL-2.1-only
#
# SELinux is reported as disabled under pseudo, and the host's answer is
# given while PSEUDO_DISABLED is set.  Skipped without libselinux.

t=./test/test-selinux-disabled
lib=libselinux.so.1

# The host's libselinux: pseudo reports SELinux as disabled, and with
# PSEUDO_DISABLED gives the same answer as without pseudo at all.
$t $lib 0,0
case $? in 0) ;; 77) exit 255 ;; *) exit 1 ;; esac
host=$(PSEUDO_UNLOAD=1 $t $lib print) || exit 1
PSEUDO_DISABLED=1 $t $lib "$host" || exit 1

# Emulate a host with SELinux enabled, whatever this one does.
$t ./test/libfake-selinux.so 0,0 || exit 1
PSEUDO_DISABLED=1 $t ./test/libfake-selinux.so 1,1 || exit 1
