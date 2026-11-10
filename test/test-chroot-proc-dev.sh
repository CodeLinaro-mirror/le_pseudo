#!/bin/bash
#
# SPDX-License-Identifier: LGPL-2.1-only
#
# Within pseudo's chroot, /proc and /dev are relative to the chroot directory
# like any other absolute path.  The host's /proc and /dev must not be
# reachable from inside the chroot, including through /proc/self/fd/<n> and
# /dev/fd/<n>, while files created under the chroot's own /proc and /dev must
# be what a program in the chroot accesses.
#
# The temporary tree has to live below $PWD so that pseudo tracks it.

tmpdir="$(mktemp -d -p "$PWD" chroot_proc_dev_XXXXXX)"
trap "rm -rf '$tmpdir'" EXIT TERM INT

echo host-stdin > "$tmpdir/stdin"
rc=0

# No /proc or /dev inside the chroot.
mkdir "$tmpdir/empty"
cp ./test/test-chroot-proc-dev "$tmpdir/empty/"
chroot "$tmpdir/empty" ./test-chroot-proc-dev empty < "$tmpdir/stdin" || rc=1

# /proc and /dev entries created inside the chroot.
root="$tmpdir/populated"
mkdir -p "$root/proc/self/fd" "$root/dev/fd"
cp ./test/test-chroot-proc-dev "$root/"
echo chroot-status > "$root/proc/self/status"
echo chroot-proc-fd0 > "$root/proc/self/fd/0"
echo chroot-dev-fd0 > "$root/dev/fd/0"
mknod "$root/dev/null" c 1 3 || rc=1
chroot "$root" ./test-chroot-proc-dev populated < "$tmpdir/stdin" || rc=1

exit $rc
