/*
 * Test open_by_handle_at() under pseudo.  The kernel needs privilege to
 * decode a file handle, so pseudo finds and opens the file itself.
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Returns 77 if the filesystem doesn't support file handles.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int failed;

#define FAIL(...) do { printf(__VA_ARGS__); failed = 1; } while (0)

static struct file_handle *
handle_for(const char *path, int flags) {
	struct file_handle *fh = malloc(sizeof(*fh) + MAX_HANDLE_SZ);
	int mount_id;

	if (!fh)
		exit(1);
	fh->handle_bytes = MAX_HANDLE_SZ;
	if (name_to_handle_at(AT_FDCWD, path, fh, &mount_id, flags) == -1) {
		if (errno == EOPNOTSUPP || errno == ENOSYS) {
			printf("name_to_handle_at not supported: %s\n", strerror(errno));
			exit(77);
		}
		printf("name_to_handle_at(%s): %s\n", path, strerror(errno));
		exit(1);
	}
	return fh;
}

/* Make the handle in another process, so this one can't have
 * remembered where it came from.
 */
static struct file_handle *
handle_from_child(const char *path) {
	struct file_handle *fh = malloc(sizeof(*fh) + MAX_HANDLE_SZ);
	int pipefd[2], status;
	pid_t pid;

	if (!fh || pipe(pipefd) == -1)
		exit(1);
	pid = fork();
	if (pid == -1)
		exit(1);
	if (pid == 0) {
		struct file_handle *child = handle_for(path, 0);
		ssize_t len = sizeof(*child) + child->handle_bytes;
		_exit(write(pipefd[1], child, len) == len ? 0 : 1);
	}
	close(pipefd[1]);
	if (read(pipefd[0], fh, sizeof(*fh) + MAX_HANDLE_SZ) < (ssize_t) sizeof(*fh))
		exit(1);
	close(pipefd[0]);
	if (waitpid(pid, &status, 0) == -1 || !WIFEXITED(status) || WEXITSTATUS(status))
		exit(WIFEXITED(status) ? WEXITSTATUS(status) : 1);
	return fh;
}

static void
check_dirfd(const char *how, int dirfd) {
	struct stat st;

	if (dirfd == -1) {
		FAIL("%s: open_by_handle_at: %s\n", how, strerror(errno));
		return;
	}
	if (fstatat(dirfd, "file", &st, 0) == -1)
		FAIL("%s: fstatat: %s\n", how, strerror(errno));
	else if (st.st_uid != 123 || st.st_gid != 456)
		FAIL("%s: file owned by %d:%d, expected 123:456\n",
			how, (int) st.st_uid, (int) st.st_gid);
	close(dirfd);
}

int
main(int argc, char *argv[]) {
	struct file_handle *fh;
	char path[4096], buf[16];
	struct stat st;
	int mount_fd, fd;
	ssize_t len;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <dir>\n", argv[0]);
		return 2;
	}
	mount_fd = open(argv[1], O_RDONLY | O_DIRECTORY);
	if (mount_fd == -1) {
		perror("open");
		return 1;
	}

	/* a directory handle, used for *at() calls */
	snprintf(path, sizeof(path), "%s/dir/file", argv[1]);
	if (chown(path, 123, 456) == -1) {
		perror("chown");
		return 1;
	}
	snprintf(path, sizeof(path), "%s/dir", argv[1]);
	fh = handle_for(path, 0);
	check_dirfd("function", open_by_handle_at(mount_fd, fh, O_RDONLY | O_DIRECTORY));
	check_dirfd("syscall", syscall(SYS_open_by_handle_at, mount_fd, fh, O_RDONLY | O_DIRECTORY));
	free(fh);

	/* a file below mount_fd that this process never named */
	snprintf(path, sizeof(path), "%s/dir/sub/data", argv[1]);
	fh = handle_from_child(path);
	fd = open_by_handle_at(mount_fd, fh, O_RDONLY);
	if (fd == -1) {
		FAIL("data: open_by_handle_at: %s\n", strerror(errno));
	} else {
		len = read(fd, buf, sizeof(buf) - 1);
		buf[len > 0 ? len : 0] = '\0';
		if (strcmp(buf, "hello\n"))
			FAIL("data: read '%s'\n", buf);
		close(fd);
	}
	free(fh);

	/* mount_fd itself */
	fh = handle_from_child(argv[1]);
	fd = open_by_handle_at(mount_fd, fh, O_RDONLY | O_DIRECTORY);
	if (fd == -1)
		FAIL("mount_fd: open_by_handle_at: %s\n", strerror(errno));
	else
		close(fd);
	free(fh);

	/* a symlink only opens with O_PATH, as the link itself */
	snprintf(path, sizeof(path), "%s/dir/link", argv[1]);
	fh = handle_from_child(path);
	fd = open_by_handle_at(mount_fd, fh, O_RDONLY);
	if (fd != -1 || errno != ELOOP)
		FAIL("link: expected ELOOP, got %d (%s)\n", fd, strerror(errno));
	fd = open_by_handle_at(mount_fd, fh, O_PATH);
	if (fd == -1)
		FAIL("link: O_PATH: %s\n", strerror(errno));
	else if (fstat(fd, &st) == -1 || !S_ISLNK(st.st_mode))
		FAIL("link: O_PATH didn't open the symlink\n");
	if (fd != -1)
		close(fd);
	free(fh);

	/* a deleted file */
	snprintf(path, sizeof(path), "%s/gone", argv[1]);
	fh = handle_from_child(path);
	unlink(path);
	fd = open_by_handle_at(mount_fd, fh, O_RDONLY);
	if (fd != -1 || errno != ESTALE)
		FAIL("gone: expected ESTALE, got %d (%s)\n", fd, strerror(errno));
	if (fd != -1)
		close(fd);

	/* the kernel's own argument checks still apply */
	fh->handle_bytes = 0;
	fd = open_by_handle_at(mount_fd, fh, O_RDONLY);
	if (fd != -1 || errno != EINVAL)
		FAIL("empty handle: expected EINVAL, got %d (%s)\n", fd, strerror(errno));
	free(fh);

	return failed;
}
