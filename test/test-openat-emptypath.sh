#!/bin/sh
#
# Test opening an empty path, with and without O_EMPTYPATH.
# SPDX-License-Identifier: LGPL-2.1-only

dir=$(pwd)/openat_emptypath_test
trap 'rm -rf "$dir"' 0
rm -rf "$dir"
mkdir -p "$dir"
touch "$dir/file"

./test/test-openat-emptypath "$dir"
