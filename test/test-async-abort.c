/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * chown() a file whose database entry still has another name, which makes
 * the server tell the client to abort.  Prints "returned" if chown()
 * returns, then does one of the following, which must deliver the abort
 * if chown() didn't:
 *   stat     a synchronous request
 *   _exit    leave without running destructors
 *   _Exit    the same, through the C99 name
 *   execvpe  run another program
 *
 * usage: test-async-abort <path> <stat|_exit|_Exit|execvpe>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

int
main(int argc, char **argv) {
	struct stat st;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <path> <stat|_exit|_Exit|execvpe>\n", argv[0]);
		return 2;
	}
	if (chown(argv[1], 1234, 5678) == -1)
		perror("chown");
	printf("returned\n");
	fflush(stdout);
	if (!strcmp(argv[2], "_exit")) {
		_exit(0);
	} else if (!strcmp(argv[2], "_Exit")) {
		_Exit(0);
	} else if (!strcmp(argv[2], "execvpe")) {
		char *args[] = { "true", NULL };
		char *env[] = { NULL };
		execvpe("true", args, env);
		perror("execvpe");
		return 2;
	}
	(void) stat(".", &st);
	printf("survived\n");
	return 0;
}
