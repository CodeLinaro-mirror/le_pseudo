/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Under pseudo, SELinux-aware programs are told SELinux is disabled
 * (YOCTO #6580), and only get the host's answer while pseudo is disabled.
 *
 * Usage: test-selinux-disabled <libselinux> <expected>|print
 *
 * Loads <libselinux> the way a program using it would, then calls
 * is_selinux_enabled() and is_selinux_mls_enabled() through the normal
 * symbol lookup, so pseudo's wrappers are used when pseudo is loaded.  The
 * answers are compared with <expected>, given as "enabled,mls", or printed.
 * Returns 77 if <libselinux> can't be loaded.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

int
main(int argc, char *argv[]) {
	int (*enabled)(void), (*mls)(void);
	char result[32];

	if (argc != 3) {
		fprintf(stderr, "usage: %s <libselinux> <expected>|print\n", argv[0]);
		return 2;
	}
	if (!dlopen(argv[1], RTLD_NOW | RTLD_GLOBAL)) {
		printf("can't load %s, skipping\n", argv[1]);
		return 77;
	}
	enabled = (int (*)(void)) dlsym(RTLD_DEFAULT, "is_selinux_enabled");
	mls = (int (*)(void)) dlsym(RTLD_DEFAULT, "is_selinux_mls_enabled");
	if (!enabled || !mls) {
		printf("%s doesn't provide is_selinux_enabled()\n", argv[1]);
		return 1;
	}
	snprintf(result, sizeof(result), "%d,%d", enabled(), mls());
	if (!strcmp(argv[2], "print")) {
		printf("%s\n", result);
		return 0;
	}
	if (strcmp(result, argv[2])) {
		printf("%s: got %s, expected %s\n", argv[1], result, argv[2]);
		return 1;
	}
	return 0;
}
