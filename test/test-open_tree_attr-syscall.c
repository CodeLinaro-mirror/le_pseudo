#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/mount.h>
#include <sys/stat.h>

#ifndef SYS_open_tree_attr

#ifndef __NR_open_tree_attr
#define __NR_open_tree_attr 467
#endif

#define SYS_open_tree_attr __NR_open_tree_attr
#endif

#define TEST_DIR "test-open-tree-dir"
#define TEST_FILE "test-open-tree-file"

static int do_open_tree_attr_syscall(int dirfd, const char *path,
                unsigned int flags)
{
    /* Using mount_attr in this call starts mount-specific privilege checks
     * which end up with EPERM.
     * The functionality when using attr == NULL is equivalent to open_tree() */
#ifdef SYS_open_tree_attr
    return syscall(SYS_open_tree_attr, dirfd, path, flags, NULL, 0);
#elif defined(__NR_open_tree_attr)
    return syscall(__NR_open_tree_attr, dirfd, path, flags, NULL, 0);
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int test_no_flags(void) {
    int treefd = -1;
    int fd = -1;
    int rc = 1;

    treefd = do_open_tree_attr_syscall(AT_FDCWD, TEST_DIR, 0);
    if (treefd == -1) {
        perror("open_tree_attr");
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

    treefd = do_open_tree_attr_syscall(basefd, TEST_DIR, 0);
    if (treefd < 0) {
        perror("open_tree_attr");
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

    treefd = do_open_tree_attr_syscall(dirfd, "", AT_EMPTY_PATH);
    if (treefd == -1) {
        perror("open_tree_attr");
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

    probefd = do_open_tree_attr_syscall(AT_FDCWD, ".", 0);
    if (probefd == -1 && errno == ENOSYS) {
        fprintf(stderr, "open_tree_attr syscall not supported, skipping.\n");
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
