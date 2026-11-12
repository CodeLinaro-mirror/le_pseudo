/*
 * Copyright (c) 2026 Yocto Project
 * guts/COPYRIGHT for information.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * int name_to_handle_at(int dirfd, const char *name, struct file_handle *handle, int *mount_id, int flags)
 *	int rc = -1;
 */

	const char *path;

	/* Encoding a handle needs no privilege, so the real call does it;
	 * pseudo only has to resolve the path (chroot, dirfd).  Real handles
	 * also let open_by_handle_at() find the file by encoding candidates
	 * and comparing.
	 *
	 * name isn't canonicalized by the wrapper, as name_to_handle_at()
	 * only follows a final symlink with AT_SYMLINK_FOLLOW, and rejects
	 * the AT_SYMLINK_NOFOLLOW the generated code adds for an empty path.
	 */
	if (name && !*name && (flags & AT_EMPTY_PATH)) {
		rc = real_name_to_handle_at(dirfd, name, handle, mount_id, flags);
	} else {
		path = pseudo_root_path(__func__, __LINE__, dirfd, name,
			(flags & AT_SYMLINK_FOLLOW) ? 0 : AT_SYMLINK_NOFOLLOW);
		rc = real_name_to_handle_at(AT_FDCWD, path, handle, mount_id, flags);
	}

/*	return rc;
 * }
 */
