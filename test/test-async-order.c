/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * chown() and chmod() are sent to the server without waiting for a reply.
 * Check that another process never sees the old ownership or mode once it
 * has been told, through a pipe or by the process exiting, that the change
 * was made.
 *
 * usage: test-async-order <directory> <count>
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

static char *dir;
static int count;
#define WRITERS 8

static void
name(char *buf, size_t len, int i) {
	snprintf(buf, len, "%s/f%d", dir, i);
}

static mode_t
mode_for(int i) {
	return (i % 2) ? 0640 : 0604;
}

static int
check(int i, int want_mode) {
	char path[4096];
	struct stat st;

	name(path, sizeof(path), i);
	if (stat(path, &st) == -1) {
		fprintf(stderr, "stat %s: %s\n", path, strerror(errno));
		return 1;
	}
	if (st.st_uid != (uid_t) (1000 + i) || st.st_gid != (gid_t) (2000 + i) ||
	    (want_mode && (st.st_mode & 07777) != mode_for(i))) {
		fprintf(stderr, "%s: got %d:%d mode %o, expected %d:%d mode %o\n",
			path, (int) st.st_uid, (int) st.st_gid,
			(unsigned) (st.st_mode & 07777), 1000 + i, 2000 + i,
			want_mode ? (unsigned) mode_for(i) : 0);
		return 1;
	}
	return 0;
}

static void
chown_one(int i) {
	char path[4096];

	name(path, sizeof(path), i);
	if (chown(path, 1000 + i, 2000 + i) == -1) {
		perror("chown");
		_exit(2);
	}
}

/* Each change is handed on through a pipe to a process that is already
 * running: chown in one process, chmod in a second, stat in a third.
 */
static int
pipe_chain(void) {
	int p12[2], p23[2];
	pid_t c2, c3;
	int i, bad = 0, status;

	if (pipe(p12) == -1 || pipe(p23) == -1) {
		perror("pipe");
		return 2;
	}
	c2 = fork();
	if (c2 == 0) {
		char path[4096];
		close(p12[1]);
		close(p23[0]);
		while (read(p12[0], &i, sizeof(i)) == sizeof(i)) {
			name(path, sizeof(path), i);
			if (chmod(path, mode_for(i)) == -1) {
				perror("chmod");
				_exit(2);
			}
			if (write(p23[1], &i, sizeof(i)) != sizeof(i))
				_exit(2);
		}
		_exit(0);
	}
	c3 = fork();
	if (c3 == 0) {
		close(p12[0]);
		close(p12[1]);
		close(p23[1]);
		while (read(p23[0], &i, sizeof(i)) == sizeof(i))
			bad += check(i, 1);
		_exit(bad ? 1 : 0);
	}
	close(p12[0]);
	close(p23[0]);
	close(p23[1]);
	/* send all the changes in a burst before handing them on, newest
	 * first, so the others ask about changes still queued behind
	 * older ones
	 */
	for (i = 0; i < count; ++i)
		chown_one(i);
	for (i = count - 1; i >= 0; --i) {
		if (write(p12[1], &i, sizeof(i)) != sizeof(i)) {
			perror("write");
			return 2;
		}
	}
	close(p12[1]);
	if (waitpid(c2, &status, 0) == -1 || !WIFEXITED(status) || WEXITSTATUS(status))
		bad = 1;
	if (waitpid(c3, &status, 0) == -1 || !WIFEXITED(status) || WEXITSTATUS(status))
		bad = 1;
	return bad;
}

/* Several children change their files at once, so the server has a
 * backlog from each, and leave with _exit(), which skips the exit-time
 * flush.  The parent checks, newest change first, as soon as they have
 * all been reaped.
 */
static int
exit_handoff(void) {
	pid_t c[WRITERS];
	int i, w, bad = 0, status;

	for (w = 0; w < WRITERS; ++w) {
		c[w] = fork();
		if (c[w] == 0) {
			for (i = 0; i < count; ++i)
				chown_one(count * (w + 1) + i);
			_exit(0);
		}
	}
	for (w = 0; w < WRITERS; ++w) {
		if (waitpid(c[w], &status, 0) == -1 || !WIFEXITED(status) || WEXITSTATUS(status))
			bad = 2;
	}
	if (bad)
		return bad;
	for (i = count * (WRITERS + 1) - 1; i >= count; --i)
		bad += check(i, 0);
	return bad ? 1 : 0;
}

int
main(int argc, char **argv) {
	char path[4096];
	int i, fd, rc;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <directory> <count>\n", argv[0]);
		return 2;
	}
	dir = argv[1];
	count = atoi(argv[2]);
	for (i = 0; i < count * (WRITERS + 1); ++i) {
		name(path, sizeof(path), i);
		fd = open(path, O_CREAT | O_WRONLY, 0600);
		if (fd == -1) {
			perror(path);
			return 2;
		}
		close(fd);
	}
	rc = pipe_chain();
	if (rc) {
		fprintf(stderr, "pipe hand-off failed\n");
		return rc;
	}
	rc = exit_handoff();
	if (rc) {
		fprintf(stderr, "exit hand-off failed\n");
		return rc;
	}
	return 0;
}
