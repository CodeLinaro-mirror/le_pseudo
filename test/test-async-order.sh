#!/bin/bash
#
# SPDX-License-Identifier: LGPL-2.1-only
#
# Ownership and mode changes are sent to the server without waiting for a
# reply.  Another process that learns of a change, through a pipe or by
# reaping the process that made it, must see the new values.  Run it
# both with and without PSEUDO_SYNC, which makes every request wait.
#
# The temporary tree has to live below $PWD so that pseudo tracks it.

tmpdir="$(mktemp -d -p "$PWD" async_order_XXXXXX)"
trap "rm -rf '$tmpdir'" EXIT TERM INT

rc=0
for sync in "" 1; do
    rm -f "$tmpdir"/f*
    if ! PSEUDO_SYNC=$sync ./test/test-async-order "$tmpdir" 500; then
        echo "FAILED: ordering broken (PSEUDO_SYNC=${sync:-unset})"
        rc=1
    fi
done
exit $rc
