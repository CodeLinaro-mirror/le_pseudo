#!/bin/bash
#
# SPDX-License-Identifier: LGPL-2.1-only
#
# Regressions guarded here: an xattr call on /proc/self/fd/<n> must address
# the file the descriptor refers to.  Path canonicalization used to expand the
# magic link with readlink(2) and then follow the result, so a context set
# through an O_PATH|O_NOFOLLOW descriptor on a symlink landed on the link
# target, and a dangling link made the call fail with ENOENT.  libselinux 3.11
# labels the rootfs that way, which left every symlink in the image unlabelled.
#
# The temporary tree has to live below $PWD so that pseudo tracks it.

tmpdir="$(mktemp -d -p "$PWD" proc_fd_XXXXXX)"
trap "rm -rf '$tmpdir'" EXIT TERM INT

./test/test-proc-fd "$tmpdir"
