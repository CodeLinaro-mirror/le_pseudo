/*
 * Test that name_to_handle_at() resolves paths the way pseudo does,
 * including inside a chroot, and only follows a final symlink with
 * AT_SYMLINK_FOLLOW.
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
#include <sys/syscall.h>
#include <unistd.h>

static struct file_handle *
get_handle(int dirfd, const char *name, int flags, int use_syscall) {
	struct file_handle *fh = malloc(sizeof(*fh) + MAX_HANDLE_SZ);
	int mount_id, rc;

	if (!fh)
		return NULL;
	fh->handle_bytes = MAX_HANDLE_SZ;
	if (use_syscall)
		rc = syscall(SYS_name_to_handle_at, dirfd, name, fh, &mount_id, flags);
	else
		rc = name_to_handle_at(dirfd, name, fh, &mount_id, flags);
	if (rc == -1) {
		if (errno == EOPNOTSUPP || errno == ENOSYS) {
			printf("name_to_handle_at not supported: %s\n", strerror(errno));
			exit(77);
		}
		printf("name_to_handle_at(%d, '%s', %#x): %s\n", dirfd, name, flags, strerror(errno));
		free(fh);
		return NULL;
	}
	return fh;
}

static int
same(const struct file_handle *a, const struct file_handle *b) {
	return a && b && a->handle_bytes == b->handle_bytes &&
		a->handle_type == b->handle_type &&
		!memcmp(a->f_handle, b->f_handle, a->handle_bytes);
}

int
main(int argc, char *argv[]) {
	struct file_handle *file, *link, *h;
	char path[4096];
	int fd, rc = 0;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <chrootdir>\n", argv[0]);
		return 2;
	}

	snprintf(path, sizeof(path), "%s/file", argv[1]);
	file = get_handle(AT_FDCWD, path, 0, 0);
	snprintf(path, sizeof(path), "%s/link", argv[1]);
	link = get_handle(AT_FDCWD, path, 0, 0);
	if (!file || !link)
		return 1;
	if (same(file, link)) {
		printf("handle for a symlink matches its target\n");
		return 1;
	}

	if (chroot(argv[1]) == -1 || chdir("/") == -1) {
		perror("chroot");
		return 1;
	}

	if (!same(get_handle(AT_FDCWD, "/file", 0, 0), file)) {
		printf("/file inside the chroot has the wrong handle\n");
		rc = 1;
	}
	if (!same(get_handle(AT_FDCWD, "/link", 0, 0), link)) {
		printf("/link without AT_SYMLINK_FOLLOW has the wrong handle\n");
		rc = 1;
	}
	if (!same(get_handle(AT_FDCWD, "/link", AT_SYMLINK_FOLLOW, 0), file)) {
		printf("/link with AT_SYMLINK_FOLLOW has the wrong handle\n");
		rc = 1;
	}
	if (!same(get_handle(AT_FDCWD, "/file", 0, 1), file)) {
		printf("/file through syscall() has the wrong handle\n");
		rc = 1;
	}

	fd = open("/file", O_RDONLY);
	if (fd == -1) {
		perror("open /file");
		return 1;
	}
	h = get_handle(fd, "", AT_EMPTY_PATH, 0);
	if (!same(h, file)) {
		printf("AT_EMPTY_PATH has the wrong handle\n");
		rc = 1;
	}
	close(fd);

	return rc;
}
