/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * void _exit(int status)
 */

	/* NOTE THAT THIS IS NEVER USED!
	 * The hand-written _exit() in ../pseudo_wrappers.c flushes
	 * asynchronous requests and exits directly.
	 */

	real__exit(status);

/*	return;
 * }
 */
