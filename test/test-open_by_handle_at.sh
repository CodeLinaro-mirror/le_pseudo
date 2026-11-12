#!/bin/sh
#
# Test open_by_handle_at() under pseudo.
# SPDX-License-Identifier: LGPL-2.1-only
#
# rc 77 indicates the filesystem doesn't support file handles, so report
# skipped (255).

dir=$(pwd)/open_by_handle_at_test
trap 'rm -rf "$dir"' 0
rm -rf "$dir"
mkdir -p "$dir/dir/sub"
touch "$dir/dir/file" "$dir/gone"
echo hello > "$dir/dir/sub/data"
ln -s file "$dir/dir/link"

./test/test-open_by_handle_at "$dir"
rc=$?
if [ "$rc" -eq 77 ]; then
	exit 255
fi
exit $rc
