#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-only
#
# Deny is the default, so the first run says nothing about the mode.  It sets
# no_new_privs itself, so it is checked whatever the machine does about that,
# and it decides the result: a skip here means this kernel or architecture has
# no filter to put in force.
./test/test-io-uring-deny deny
case $? in 0);; 77) exit 255;; *) exit 1;; esac
# Passthrough can only fail the test, not skip it.  A filter installed by an
# ancestor cannot be removed, so where something upstream of the test has
# already denied io_uring - including pseudo itself, when it was started
# somewhere no_new_privs was already set - passthrough is not reachable, and
# the run above is what there was to check.
PSEUDO_IO_URING_SECCOMP=0 ./test/test-io-uring-deny passthrough
case $? in 0 | 77);; *) exit 1;; esac
