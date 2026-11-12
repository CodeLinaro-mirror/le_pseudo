/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Operations submitted through an io_uring bypass libpseudo, so pseudo
 * reports io_uring as unsupported to callers using syscall(), such as
 * libuv, which then fall back to ordinary calls.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/* The numbers are the same on every architecture using the common table. */
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif
#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter 426
#endif
#ifndef __NR_io_uring_register
#define __NR_io_uring_register 427
#endif

static int
check(const char *name, long rc) {
	if (rc != -1 || errno != ENOSYS) {
		printf("%s: expected ENOSYS, got %ld (%s)\n", name, rc, strerror(errno));
		if (rc >= 0)
			close(rc);
		return 1;
	}
	return 0;
}

int
main(void) {
	char params[120] = { 0 };	/* struct io_uring_params */
	int rc = 0;

	rc |= check("io_uring_setup", syscall(__NR_io_uring_setup, 1, params));
	rc |= check("io_uring_enter", syscall(__NR_io_uring_enter, -1, 0, 0, 0, NULL, 0));
	rc |= check("io_uring_register", syscall(__NR_io_uring_register, -1, 0, NULL, 0));
	return rc;
}
