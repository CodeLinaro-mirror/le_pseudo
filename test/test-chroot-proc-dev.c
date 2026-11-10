/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Run inside pseudo's chroot.  Absolute paths, including /proc and /dev, are
 * relative to the chroot directory, so the host's /proc and /dev must not be
 * reachable from inside it, while files created under the chroot's own /proc
 * and /dev must be.
 *
 * usage: test-chroot-proc-dev empty|populated
 *
 *   empty      the chroot has no /proc or /dev; every access must fail with
 *              ENOENT, including /proc/self/fd/<n> and /dev/fd/<n> for a
 *              descriptor this program opened itself.
 *   populated  the chroot has the files created by test-chroot-proc-dev.sh;
 *              they must be what is accessed.  Standard input is a host file
 *              containing "host-stdin", which must not be what is read.
 *
 * Exit status: 0 all checks passed, 1 a check failed.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

static int failures;

static void
fail(const char *what, const char *detail)
{
	printf("  FAIL  %-52s %s\n", what, detail);
	++failures;
}

static void
pass(const char *what)
{
	printf("  PASS  %s\n", what);
}

/* The path must not exist inside the chroot. */
static void
expect_enoent(const char *what, const char *path, int is_readlink)
{
	char buf[256];
	struct stat st;
	int rc;

	if (is_readlink)
		rc = readlink(path, buf, sizeof buf) == -1 ? -1 : 0;
	else
		rc = stat(path, &st);
	if (rc == 0)
		fail(what, "path exists");
	else if (errno != ENOENT)
		fail(what, strerror(errno));
	else
		pass(what);
}

/* The path must open and its first line must be want. */
static void
expect_content(const char *what, const char *path, const char *want)
{
	char buf[256];
	ssize_t n;
	int fd = open(path, O_RDONLY);

	if (fd == -1) {
		fail(what, strerror(errno));
		return;
	}
	n = read(fd, buf, sizeof buf - 1);
	close(fd);
	buf[n > 0 ? n : 0] = '\0';
	buf[strcspn(buf, "\n")] = '\0';
	if (strcmp(buf, want) == 0)
		pass(what);
	else
		fail(what, buf);
}

static int
check_empty(void)
{
	char path[64];
	int fd;

	expect_enoent("/proc is not the host's /proc", "/proc", 0);
	expect_enoent("/proc/self/status is not reachable", "/proc/self/status", 0);
	expect_enoent("/dev is not the host's /dev", "/dev", 0);
	expect_enoent("/dev/null is not reachable", "/dev/null", 0);

	/* A descriptor this program opened: pseudo knows its path, and must
	 * still not resolve /proc/self/fd/<n> or /dev/fd/<n> through the
	 * host's /proc.
	 */
	fd = open("/target", O_CREAT | O_RDWR, 0644);
	if (fd == -1) {
		perror("/target");
		return 1;
	}
	snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
	expect_enoent("/proc/self/fd/<n> does not resolve", path, 0);
	expect_enoent("/proc/self/fd/<n> is not a link", path, 1);
	snprintf(path, sizeof path, "/proc/%ld/fd/%d", (long) getpid(), fd);
	expect_enoent("/proc/<own pid>/fd/<n> does not resolve", path, 0);
	snprintf(path, sizeof path, "/dev/fd/%d", fd);
	expect_enoent("/dev/fd/<n> does not resolve", path, 0);
	close(fd);

	if (mkdir("/subdir", 0755) == -1) {
		perror("/subdir");
		return 1;
	}
	fd = open("/subdir", O_RDONLY | O_DIRECTORY);
	if (fd == -1) {
		perror("/subdir");
		return 1;
	}
	snprintf(path, sizeof path, "/proc/self/fd/%d/.", fd);
	expect_enoent("/proc/self/fd/<n>/<path> does not resolve", path, 0);
	close(fd);
	return 0;
}

static int
check_populated(void)
{
	struct stat st;
	int fd;

	expect_content("/proc/self/status comes from the chroot",
		       "/proc/self/status", "chroot-status");
	expect_content("/proc/self/fd/0 comes from the chroot",
		       "/proc/self/fd/0", "chroot-proc-fd0");
	expect_content("/dev/fd/0 comes from the chroot",
		       "/dev/fd/0", "chroot-dev-fd0");

	if (stat("/dev/null", &st) == -1) {
		fail("/dev/null created in the chroot exists", strerror(errno));
	} else if (!S_ISCHR(st.st_mode) || major(st.st_rdev) != 1 ||
		   minor(st.st_rdev) != 3) {
		fail("/dev/null created in the chroot exists", "not chr 1:3");
	} else {
		pass("/dev/null created in the chroot exists");
	}
	fd = open("/dev/null", O_WRONLY);
	if (fd == -1) {
		fail("/dev/null created in the chroot opens", strerror(errno));
	} else {
		pass("/dev/null created in the chroot opens");
		close(fd);
	}

	/* Nothing was created for this one, so it must not exist. */
	expect_enoent("/proc/self/cmdline is not the host's",
		      "/proc/self/cmdline", 0);
	return 0;
}

int
main(int argc, char **argv)
{
	int rc;

	if (argc != 2) {
		fprintf(stderr, "usage: %s empty|populated\n", argv[0]);
		return 1;
	}
	if (!strcmp(argv[1], "empty")) {
		rc = check_empty();
	} else if (!strcmp(argv[1], "populated")) {
		rc = check_populated();
	} else {
		fprintf(stderr, "usage: %s empty|populated\n", argv[0]);
		return 1;
	}
	if (rc)
		return rc;

	printf("%s: %d check(s) failed\n", failures ? "FAIL" : "OK", failures);
	return failures ? 1 : 0;
}
