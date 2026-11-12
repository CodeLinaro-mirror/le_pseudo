/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Does deny deny, and does passthrough stay out of the way?
 *
 * Deny needs a filter, a filter needs no_new_privs, and pseudo will not set
 * it on an application's behalf - so the test sets it and re-executes itself.
 * The copy which comes back has libpseudo loaded afresh with the precondition
 * met, and it is that copy which asks the kernel for a ring.  Without that the
 * test would only ever see the fallback on a machine where no_new_privs is
 * unset, which is most of them.
 *
 * Everything which is not pseudo's doing is a skip rather than a failure: a
 * kernel with no seccomp to install a filter into, an architecture pseudo has
 * no audit value for, an io_uring which has been switched off.  The one thing
 * reported as a failure is a filter being in force and io_uring working
 * anyway, because that is pseudo not keeping its word.
 *
 * pseudo's syscall() wrapper refuses io_uring in both modes, so both are
 * checked with the system call made directly, as liburing does, which only
 * the filter can see.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../ports/linux/io_uring_syscalls.h"

#define SKIP 77

#ifndef PSEUDO_HAVE_IO_URING_SYSCALLS
int
main(void)
{
	return SKIP;
}
#else

/* Old sysroots may not have them, and they are part of the kernel ABI. */
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
#ifndef PR_GET_SECCOMP
#define PR_GET_SECCOMP 21
#endif

/* io_uring_setup() needs somewhere to put what it negotiated, and the
 * argument is rejected before it is written when the call is refused, so the
 * size is all that has to be right. */
struct params {
	unsigned char opaque[120];
};

/* Make the system call without libc, so pseudo's syscall() wrapper can't
 * answer it.  Returns -1 and sets errno on failure, as syscall() does.
 */
#if defined(__x86_64__) && !defined(__ILP32__)
#define HAVE_RAW_SYSCALL 1
static long
raw_syscall(long n, long a, long b, long c, long d, long e, long f)
{
	register long r10 __asm__("r10") = d;
	register long r8 __asm__("r8") = e;
	register long r9 __asm__("r9") = f;
	long ret;

	__asm__ volatile ("syscall"
		: "=a"(ret)
		: "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
		: "rcx", "r11", "memory");
	if (ret < 0 && ret > -4096) {
		errno = -ret;
		return -1;
	}
	return ret;
}
#elif defined(__aarch64__)
#define HAVE_RAW_SYSCALL 1
static long
raw_syscall(long n, long a, long b, long c, long d, long e, long f)
{
	register long x8 __asm__("x8") = n;
	register long x0 __asm__("x0") = a;
	register long x1 __asm__("x1") = b;
	register long x2 __asm__("x2") = c;
	register long x3 __asm__("x3") = d;
	register long x4 __asm__("x4") = e;
	register long x5 __asm__("x5") = f;

	__asm__ volatile ("svc 0"
		: "+r"(x0)
		: "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
		: "memory");
	if (x0 < 0 && x0 > -4096) {
		errno = -x0;
		return -1;
	}
	return x0;
}
#elif defined(__riscv) && __riscv_xlen == 64
#define HAVE_RAW_SYSCALL 1
static long
raw_syscall(long n, long a, long b, long c, long d, long e, long f)
{
	register long a7 __asm__("a7") = n;
	register long a0 __asm__("a0") = a;
	register long a1 __asm__("a1") = b;
	register long a2 __asm__("a2") = c;
	register long a3 __asm__("a3") = d;
	register long a4 __asm__("a4") = e;
	register long a5 __asm__("a5") = f;

	__asm__ volatile ("ecall"
		: "+r"(a0)
		: "r"(a7), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5)
		: "memory");
	if (a0 < 0 && a0 > -4096) {
		errno = -a0;
		return -1;
	}
	return a0;
}
#endif

#ifdef HAVE_RAW_SYSCALL
/* The two calls which need no ring, asked for with a descriptor which is not
 * one.  A refusal is decided from the syscall number alone, so the arguments
 * only have to be ones the kernel would not fault on. */
static long
io_uring_other(int which)
{
	if (which == 0)
		return raw_syscall(SYS_io_uring_enter, -1, 0, 0, 0, 0, 0);
	return raw_syscall(SYS_io_uring_register, -1, 0, 0, 0, 0, 0);
}

static const char *const other_name[] = {
	"io_uring_enter", "io_uring_register"
};

static int
check_deny(void)
{
	struct params p;
	long rc;
	int which;

	/* io_uring_setup() first, because its answer is what says whether the
	 * filter is in force at all. */
	memset(&p, 0, sizeof(p));
	errno = 0;
	rc = raw_syscall(SYS_io_uring_setup, 8, (long) &p, 0, 0, 0, 0);
	if (rc >= 0) {
		close((int) rc);
		if (prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != 2) {
			/* No filter is in force, so this kernel or this
			 * architecture could not have one installed and there
			 * is nothing here to test. */
			fprintf(stderr,
				"test-io-uring-deny: no seccomp filter in force, skipping\n");
			return SKIP;
		}
		fprintf(stderr,
			"test-io-uring-deny: io_uring_setup was not denied\n");
		return 1;
	}
	if (errno != ENOSYS) {
		/* Refused, but not by pseudo: a kernel which never had
		 * io_uring, or one with it switched off.  Deny's promise is
		 * kept either way and there is nothing to tell apart. */
		fprintf(stderr,
			"test-io-uring-deny: io_uring unavailable (errno %d), skipping\n",
			errno);
		return SKIP;
	}

	/* The filter is in force, so the other two have to answer the same
	 * way; anything else is pseudo covering only part of what it said. */
	for (which = 0; which < 2; ++which) {
		errno = 0;
		rc = io_uring_other(which);
		if (rc < 0 && errno == ENOSYS)
			continue;
		fprintf(stderr,
			"test-io-uring-deny: %s was not denied (rc %ld, errno %d)\n",
			other_name[which], rc, rc < 0 ? errno : 0);
		return 1;
	}
	return 0;
}

static int
check_passthrough(void)
{
	struct params p;
	long rc;

	memset(&p, 0, sizeof(p));
	errno = 0;
	rc = raw_syscall(SYS_io_uring_setup, 8, (long) &p, 0, 0, 0, 0);
	if (rc >= 0) {
		close((int) rc);
		return 0;
	}
	/* ENOSYS from a filter an ancestor installed, which cannot be removed,
	 * or from a kernel which never had io_uring; EPERM or EACCES where it
	 * has been switched off.  None of them is pseudo letting io_uring
	 * through, and none can be told from the others here. */
	fprintf(stderr,
		"test-io-uring-deny: io_uring unavailable (errno %d), skipping\n",
		errno);
	return SKIP;
}
#endif /* HAVE_RAW_SYSCALL */

int
main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s deny|passthrough\n", argv[0]);
		return 1;
	}
	if (strcmp(argv[1], "passthrough") && strcmp(argv[1], "deny")) {
		fprintf(stderr, "usage: %s deny|passthrough\n", argv[0]);
		return 1;
	}

#ifndef HAVE_RAW_SYSCALL
	fprintf(stderr,
		"test-io-uring-deny: no direct system call for this architecture, skipping\n");
	return SKIP;
#else
	if (!strcmp(argv[1], "passthrough"))
		return check_passthrough();

	/* Deny, and this is the first of the two passes: arrange the
	 * precondition and come back through libpseudo's constructor with it
	 * in place. */
	if (argc < 3) {
		char *args[4];

		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
			fprintf(stderr,
				"test-io-uring-deny: no_new_privs unavailable (errno %d), skipping\n",
				errno);
			return SKIP;
		}
		args[0] = argv[0];
		args[1] = argv[1];
		args[2] = (char *) "installed";
		args[3] = NULL;
		execv(argv[0], args);
		fprintf(stderr,
			"test-io-uring-deny: cannot re-execute %s (errno %d), skipping\n",
			argv[0], errno);
		return SKIP;
	}

	return check_deny();
#endif
}
#endif /* PSEUDO_HAVE_IO_URING_SYSCALLS */
