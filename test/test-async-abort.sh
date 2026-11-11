#!/bin/bash
#
# SPDX-License-Identifier: LGPL-2.1-only
#
# A chown() whose database entry has another name makes the server tell
# the client to abort.  chown() is sent without waiting, so the client
# must still abort: at its next request that waits for a reply, or when
# it leaves with _exit() or _Exit() or execs another program.  With PSEUDO_SYNC set,
# it must abort inside chown() itself.
#
# The temporary tree has to live below $PWD so that pseudo tracks it.

tmpdir="$(mktemp -d -p "$PWD" async_abort_XXXXXX)"
trap "rm -rf '$tmpdir'" EXIT TERM INT

rc=0
check() {
    local sync="$1" how="$2" expect="$3" out status
    : > "$tmpdir/a"
    # rename it behind pseudo's back, so the database still says "a"
    PSEUDO_DISABLED=1 mv "$tmpdir/a" "$tmpdir/b"
    out=$(PSEUDO_SYNC=$sync ./test/test-async-abort "$tmpdir/b" "$how" 2>/dev/null)
    status=$?
    # put the name back so the database entry can be removed cleanly
    PSEUDO_DISABLED=1 mv "$tmpdir/b" "$tmpdir/a"
    rm -f "$tmpdir/a"
    if [ $status -ne 134 ]; then
        echo "FAILED: $how: expected abort (PSEUDO_SYNC=${sync:-unset}), got status $status"
        rc=1
    elif [ "$out" != "$expect" ]; then
        echo "FAILED: $how: PSEUDO_SYNC=${sync:-unset}: expected output '$expect', got '$out'"
        rc=1
    fi
}

for how in stat _exit _Exit execvpe; do
    check "" $how "returned"
done
check 1 stat ""
exit $rc
