/*
 * Copyright (c) 2026 Yocto Project
 * guts/COPYRIGHT for information.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * int open_by_handle_at(int mount_fd, struct file_handle *handle, int flags)
 *	int rc = -1;
 */

	PSEUDO_STATBUF buf;
	char procpath[32];
	char *path;
	ssize_t len;
	int save_errno;

	/* always emulated, as decoding a handle needs privilege */
	rc = pseudo_open_by_handle(mount_fd, handle, flags);
	if (rc == -1)
		return rc;
	save_errno = errno;

	/* A handle names an inode, not a path.  Record the path the kernel
	 * reports for the descriptor, if it still names the same file, so
	 * that calls using the descriptor, including *at() calls relative
	 * to it, can be resolved.
	 */
	snprintf(procpath, sizeof(procpath), "/proc/self/fd/%d", rc);
	path = malloc(pseudo_path_max());
	if (path) {
		len = real_readlink(procpath, path, pseudo_path_max() - 1);
		if (len > 0 && path[0] == '/') {
			path[len] = '\0';
			if (!pseudo_client_path_matches_fd(path, rc, 1)) {
				free(path);
				path = NULL;
			}
		} else {
			free(path);
			path = NULL;
		}
	}

	if (path) {
		if (base_fstat(rc, &buf) != -1)
			pseudo_client_op(OP_OPEN, 0, rc, -1, path, &buf);
		else
			pseudo_client_op(OP_OPEN, 0, rc, -1, path, 0);
		free(path);
	} else {
		pseudo_debug(PDBGF_FILE, "open_by_handle_at: no path for fd %d\n", rc);
		/* drop any path left over from a close pseudo didn't see */
		pseudo_client_op(OP_CLOSE, 0, rc, -1, 0, 0);
	}
	errno = save_errno;

/*	return rc;
 * }
 */
