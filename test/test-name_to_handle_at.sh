#!/bin/sh
#
# Test name_to_handle_at() path resolution, including inside a chroot.
# SPDX-License-Identifier: LGPL-2.1-only
#
# rc 77 indicates the filesystem doesn't support file handles, so report
# skipped (255).

dir=$(pwd)/name_to_handle_at_test
trap 'rm -rf "$dir"' 0
rm -rf "$dir"
mkdir -p "$dir"
touch "$dir/file"
ln -s file "$dir/link"

./test/test-name_to_handle_at "$dir"
rc=$?
if [ "$rc" -eq 77 ]; then
	exit 255
fi
exit $rc
