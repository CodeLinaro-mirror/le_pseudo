#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>

#define TEST_DIR "test-open-tree-dir"
#define TEST_FILE "test-open-tree-file"

/*
 * Older glibc versions (< 2.36) do not provide open_tree().  Declare it
 * weak so the test still links; at runtime it resolves to glibc's or
 * libpseudo's open_tree if either provides it, otherwise it is NULL and
 * the test is skipped.
 */
extern int open_tree(int dirfd, const char *path, unsigned int flags) __attribute__((weak));

static int test_no_flags(void) {
    int treefd = -1;
    int fd = -1;
    int rc = 1;

    treefd = open_tree(AT_FDCWD, TEST_DIR, 0);
    if (treefd == -1) {
        perror("open_tree");
        goto out;
    }

    fd = openat(treefd, TEST_FILE, O_CREAT | O_RDWR, 0666);
    if (fd < 0) {
        perror("openat");
        goto out;
    }

    rc = 0;
out:
    if (treefd != -1) {
        close(treefd);
    }
    if (fd != -1) {
        close(fd);
    }
    return rc;
}

static int test_relative_dirfd(void) {
    int basefd = -1;
    int treefd = -1;
    int fd = -1;
    int rc = 1;

    basefd = open(".", O_PATH | O_DIRECTORY);
    if (basefd < 0) {
        perror("open");
        goto out;
    }

    treefd = open_tree(basefd, TEST_DIR, 0);
    if (treefd < 0) {
        perror("open_tree");
        goto out;
    }

    fd = openat(treefd, TEST_FILE, O_CREAT | O_RDWR, 0666);
    if (fd < 0) {
        perror("openat");
        goto out;
    }

    rc = 0;
out:
    if (basefd != -1) {
        close(basefd);
    }
    if (treefd != -1) {
        close(treefd);
    }
    if (fd != -1) {
        close(fd);
    }
    return rc;
}

static int test_at_empty_path(void) {
    int treefd = -1;
    int dirfd = -1;
    int fd = -1;
    int rc = 1;

    dirfd = open(TEST_DIR, O_PATH | O_DIRECTORY);
    if (dirfd < 0) {
        perror("open");
        goto out;
    }

    treefd = open_tree(dirfd, "", AT_EMPTY_PATH);
    if (treefd == -1) {
        perror("open_tree");
        goto out;
    }

    fd = openat(treefd, TEST_FILE, O_CREAT | O_RDWR, 0666);
    if (fd < 0) {
        perror("openat");
        goto out;
    }

    rc = 0;
out:
    if (dirfd != -1) {
        close(dirfd);
    }
    if (treefd != -1) {
        close(treefd);
    }
    if (fd != -1) {
        close(fd);
    }
    return rc;
}

static void cleanup(void) {
    if (unlink(TEST_DIR "/" TEST_FILE) == -1 && errno != ENOENT) {
        perror("unlink");
    }
    if (rmdir(TEST_DIR) == -1 && errno != ENOENT) {
        perror("rmdir");
    }
}

int main(void) {
    int probefd;

    if (!open_tree) {
        fprintf(stderr, "open_tree() not available, skipping.\n");
        return 77;
    }

    /* pseudo exports open_tree() but returns ENOSYS if libc lacks it */
    probefd = open_tree(AT_FDCWD, ".", 0);
    if (probefd == -1 && errno == ENOSYS) {
        fprintf(stderr, "open_tree() returned ENOSYS, skipping.\n");
        return 77;
    }
    if (probefd != -1) {
        close(probefd);
    }

    cleanup();

    if (mkdir(TEST_DIR, 0777) == -1) {
        perror("mkdir");
        return 1;
    }

    int rc = test_no_flags();
    rc |= test_at_empty_path();
    rc |= test_relative_dirfd();

    cleanup();

    return rc;
}
