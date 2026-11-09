#!/bin/sh

# rc 77 indicates open_tree() is not available, so report skipped (255).
# This usually indicates that glibc does not have the open_tree function.
run_test() {
	"$@"
	rc=$?
	if [ "$rc" -eq 77 ]; then
		exit 255
	fi
	return "$rc"
}

run_test ./test/test-open_tree
rc1=$?

run_test env PSEUDO_IGNORE_PATHS=/ ./test/test-open_tree
rc2=$?

exit $((rc1 | rc2))
