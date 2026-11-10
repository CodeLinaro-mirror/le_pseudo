/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Check that xattr operations on /proc/self/fd/<n> address the file the
 * descriptor refers to, and not the path the magic link prints.
 *
 * A descriptor opened with O_PATH|O_NOFOLLOW on a symlink denotes the
 * symlink itself, so a context set through it must land on the link and
 * leave the target alone.  A descriptor opened by following a symlink
 * denotes the target, so the context must land there instead.
 *
 * /proc/<pid>/fd/<n> naming this process must behave like /proc/self, while
 * naming another process must address that process's descriptor, not the
 * one this process has open under the same number.
 *
 * Exit status: 0 all checks passed, 1 a check failed, 255 skipped because
 * the platform has no xattr support.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>

#define CTX "security.selinux"

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

/* Read the context of path itself, without following a final symlink.
 * Returns NULL when there is none.
 */
static const char *
get_ctx(const char *path, char *buf, size_t buflen)
{
	ssize_t n = lgetxattr(path, CTX, buf, buflen - 1);

	if (n < 0)
		return NULL;
	buf[n] = '\0';
	return buf;
}

static void
expect_ctx(const char *what, const char *path, const char *want)
{
	char buf[256];
	const char *got = get_ctx(path, buf, sizeof buf);

	if (!want) {
		if (got)
			fail(what, got);
		else
			pass(what);
		return;
	}
	if (got && strcmp(got, want) == 0)
		pass(what);
	else
		fail(what, got ? got : "<no context>");
}

/* Set the context through the descriptor, the same way libselinux does when
 * it pins a file: path-based call, no extra flags.
 */
static int
set_via_fd(int fd, const char *value)
{
	char path[64];

	snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
	return setxattr(path, CTX, value, strlen(value) + 1, 0);
}

/* As set_via_fd(), but naming the process by number. */
static int
set_via_pid_fd(pid_t pid, int fd, const char *value)
{
	char path[64];

	snprintf(path, sizeof path, "/proc/%ld/fd/%d", (long) pid, fd);
	return setxattr(path, CTX, value, strlen(value) + 1, 0);
}

/* Set a context through another process's descriptor <fd>, which refers to
 * "theirs" in the child, while this process's descriptor <fd> refers to
 * "mine".  Returns -1 if the setup failed.
 */
static int
set_via_other_process(const char *dir, int fd, const char *value)
{
	char path[512];
	int ready[2], release[2];
	pid_t child;
	char c;
	int rc, status;

	if (pipe(ready) == -1 || pipe(release) == -1) {
		perror("pipe");
		return -1;
	}
	child = fork();
	if (child == -1) {
		perror("fork");
		return -1;
	}
	if (child == 0) {
		int other;

		close(ready[0]);
		close(release[1]);
		snprintf(path, sizeof path, "%s/theirs", dir);
		other = open(path, O_RDONLY);
		if (other == -1 || dup2(other, fd) == -1)
			_exit(1);
		close(other);
		if (write(ready[1], "r", 1) != 1)
			_exit(1);
		/* hold the descriptor until the parent is done */
		while (read(release[0], &c, 1) > 0)
			;
		_exit(0);
	}
	close(ready[1]);
	close(release[0]);
	if (read(ready[0], &c, 1) != 1) {
		fprintf(stderr, "child failed to set up its descriptor\n");
		close(release[1]);
		waitpid(child, &status, 0);
		return -1;
	}
	rc = set_via_pid_fd(child, fd, value);
	if (rc == -1)
		fail("context set through another process's descriptor",
		     strerror(errno));
	else
		pass("context set through another process's descriptor");
	close(ready[0]);
	close(release[1]);
	waitpid(child, &status, 0);
	return 0;
}

int
main(int argc, char **argv)
{
	const char *dir = argc > 1 ? argv[1] : ".";
	char path[512];
	int fd;

	snprintf(path, sizeof path, "%s/file", dir);
	if (close(open(path, O_CREAT | O_WRONLY, 0644)) == -1) {
		perror(path);
		return 1;
	}
	snprintf(path, sizeof path, "%s/link", dir);
	if (symlink("file", path) == -1) {
		perror(path);
		return 1;
	}
	snprintf(path, sizeof path, "%s/dangling", dir);
	if (symlink("/nonexistent/xyz", path) == -1) {
		perror(path);
		return 1;
	}

	/* 1. O_PATH|O_NOFOLLOW on a symlink: label the link, not its target. */
	snprintf(path, sizeof path, "%s/link", dir);
	fd = open(path, O_PATH | O_NOFOLLOW);
	if (fd == -1) {
		perror(path);
		return 1;
	}
	if (set_via_fd(fd, "onlink") == -1 && errno == ENOTSUP) {
		printf("  SKIP  xattr support unavailable\n");
		return 255;
	}
	close(fd);

	snprintf(path, sizeof path, "%s/link", dir);
	expect_ctx("context landed on the symlink", path, "onlink");
	snprintf(path, sizeof path, "%s/file", dir);
	expect_ctx("context did not land on the target", path, NULL);

	/* 2. A dangling symlink must not make the operation fail. */
	snprintf(path, sizeof path, "%s/dangling", dir);
	fd = open(path, O_PATH | O_NOFOLLOW);
	if (fd == -1) {
		perror(path);
		return 1;
	}
	if (set_via_fd(fd, "ondangling") == -1) {
		fail("context set on a dangling symlink", strerror(errno));
	} else {
		pass("context set on a dangling symlink");
	}
	close(fd);
	expect_ctx("context landed on the dangling link", path, "ondangling");

	/* 3. A descriptor obtained by following a symlink denotes the target. */
	snprintf(path, sizeof path, "%s/target", dir);
	if (close(open(path, O_CREAT | O_WRONLY, 0644)) == -1) {
		perror(path);
		return 1;
	}
	snprintf(path, sizeof path, "%s/link2", dir);
	if (symlink("target", path) == -1) {
		perror(path);
		return 1;
	}
	fd = open(path, O_RDONLY);
	if (fd == -1) {
		perror(path);
		return 1;
	}
	if (set_via_fd(fd, "ontarget") == -1) {
		fail("context set through a followed descriptor", strerror(errno));
	} else {
		pass("context set through a followed descriptor");
	}
	close(fd);

	snprintf(path, sizeof path, "%s/target", dir);
	expect_ctx("context landed on the target", path, "ontarget");
	snprintf(path, sizeof path, "%s/link2", dir);
	expect_ctx("context did not land on the link", path, NULL);

	/* 4. /proc/<other pid>/fd/<n> is the other process's descriptor, not
	 *    the one this process has open as <n>.
	 */
	snprintf(path, sizeof path, "%s/mine", dir);
	if (close(open(path, O_CREAT | O_WRONLY, 0644)) == -1) {
		perror(path);
		return 1;
	}
	snprintf(path, sizeof path, "%s/theirs", dir);
	if (close(open(path, O_CREAT | O_WRONLY, 0644)) == -1) {
		perror(path);
		return 1;
	}
	snprintf(path, sizeof path, "%s/mine", dir);
	fd = open(path, O_RDONLY);
	if (fd == -1) {
		perror(path);
		return 1;
	}
	if (set_via_other_process(dir, fd, "onother") == -1)
		return 1;
	close(fd);

	snprintf(path, sizeof path, "%s/theirs", dir);
	expect_ctx("context landed on the other process's file", path, "onother");
	snprintf(path, sizeof path, "%s/mine", dir);
	expect_ctx("context did not land on this process's file", path, NULL);

	/* 5. /proc/<own pid>/fd/<n> behaves like /proc/self/fd/<n>. */
	snprintf(path, sizeof path, "%s/file3", dir);
	if (close(open(path, O_CREAT | O_WRONLY, 0644)) == -1) {
		perror(path);
		return 1;
	}
	snprintf(path, sizeof path, "%s/link3", dir);
	if (symlink("file3", path) == -1) {
		perror(path);
		return 1;
	}
	fd = open(path, O_PATH | O_NOFOLLOW);
	if (fd == -1) {
		perror(path);
		return 1;
	}
	if (set_via_pid_fd(getpid(), fd, "onpidlink") == -1) {
		fail("context set through /proc/<own pid>/fd", strerror(errno));
	} else {
		pass("context set through /proc/<own pid>/fd");
	}
	close(fd);

	snprintf(path, sizeof path, "%s/link3", dir);
	expect_ctx("context landed on the symlink via own pid", path, "onpidlink");
	snprintf(path, sizeof path, "%s/file3", dir);
	expect_ctx("context did not land on the target via own pid", path, NULL);

	printf("%s: %d check(s) failed\n", failures ? "FAIL" : "OK", failures);
	return failures ? 1 : 0;
}
