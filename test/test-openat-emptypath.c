/*
 * Test opening an empty path with openat() and openat2(), which only
 * names dirfd with O_EMPTYPATH (Linux 7.2), the way the kernel does.
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#if __has_include (<linux/openat2.h>)
# include <linux/openat2.h>
#else
struct open_how {
	unsigned long long flags;
	unsigned long long mode;
	unsigned long long resolve;
};
#endif

#ifndef O_EMPTYPATH
#define O_EMPTYPATH (1 << 26)
#endif

static int failed;

#define FAIL(...) do { printf(__VA_ARGS__); failed = 1; } while (0)

static int
do_openat2(int dirfd, const char *path, unsigned long long flags) {
	struct open_how how = { .flags = flags };

	return syscall(SYS_openat2, dirfd, path, &how, sizeof(how));
}

/* fd should be dir, with pseudo knowing its path */
static void
check_reopened(const char *how, int fd) {
	struct stat st;

	if (fd == -1) {
		if (errno == ENOENT || errno == EINVAL)
			printf("%s: O_EMPTYPATH not supported by the kernel, skipping\n", how);
		else
			FAIL("%s: %s\n", how, strerror(errno));
		return;
	}
	if (fstatat(fd, "file", &st, 0) == -1)
		FAIL("%s: fstatat: %s\n", how, strerror(errno));
	else if (st.st_uid != 123 || st.st_gid != 456)
		FAIL("%s: file owned by %d:%d, expected 123:456\n",
			how, (int) st.st_uid, (int) st.st_gid);
	close(fd);
}

int
main(int argc, char *argv[]) {
	char path[4096];
	int dfd, pfd, fd;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <dir>\n", argv[0]);
		return 2;
	}
	snprintf(path, sizeof(path), "%s/file", argv[1]);
	if (chown(path, 123, 456) == -1) {
		perror("chown");
		return 1;
	}
	dfd = open(argv[1], O_RDONLY | O_DIRECTORY);
	pfd = open(argv[1], O_PATH | O_DIRECTORY);
	if (dfd == -1 || pfd == -1) {
		perror("open");
		return 1;
	}

	fd = openat(dfd, "", O_RDONLY);
	if (fd != -1 || errno != ENOENT)
		FAIL("openat without O_EMPTYPATH: expected ENOENT, got %d (%s)\n",
			fd, strerror(errno));
	if (fd != -1)
		close(fd);
	fd = do_openat2(dfd, "", O_RDONLY);
	if (fd != -1 || errno != ENOENT)
		FAIL("openat2 without O_EMPTYPATH: expected ENOENT, got %d (%s)\n",
			fd, strerror(errno));
	if (fd != -1)
		close(fd);

	check_reopened("openat", openat(pfd, "", O_RDONLY | O_DIRECTORY | O_EMPTYPATH));
	check_reopened("openat2", do_openat2(pfd, "", O_RDONLY | O_DIRECTORY | O_EMPTYPATH));
	if (fchdir(dfd) == -1) {
		perror("fchdir");
		return 1;
	}
	check_reopened("openat AT_FDCWD", openat(AT_FDCWD, "", O_RDONLY | O_DIRECTORY | O_EMPTYPATH));
	check_reopened("openat2 AT_FDCWD", do_openat2(AT_FDCWD, "", O_RDONLY | O_DIRECTORY | O_EMPTYPATH));

	return failed;
}
