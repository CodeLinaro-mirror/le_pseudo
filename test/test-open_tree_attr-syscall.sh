#!/bin/sh

# rc 77 indicates the open_tree_attr syscall is not supported (ENOSYS),
# so report skipped (255).  This usually indicates an older kernel.
run_test() {
	"$@"
	rc=$?
	if [ "$rc" -eq 77 ]; then
		exit 255
	fi
	return "$rc"
}

run_test ./test/test-open_tree_attr-syscall
rc1=$?

run_test env PSEUDO_IGNORE_PATHS=/ ./test/test-open_tree_attr-syscall
rc2=$?

exit $((rc1 | rc2))
