/*
 * Copyright (c) 2026 Yocto Project
 * guts/COPYRIGHT for information.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * int is_selinux_enabled(void)
 *	int rc = -1;
 */

	/* SELinux-aware programs label the files they create or install
	 * using the host's policy.  pseudo only records the label, which is
	 * wrong for target files and leaks the host policy into the build,
	 * and programs which then hand it back to the kernel, e.g. through
	 * /proc/self/attr/fscreate, can be refused (YOCTO #6580).  So report
	 * SELinux as disabled, as on a host without it.  Labels set
	 * explicitly, e.g. by setfiles, are still recorded.  The host's
	 * answer is only given while pseudo is disabled.
	 */
	rc = 0;

/*	return rc;
 * }
 */
