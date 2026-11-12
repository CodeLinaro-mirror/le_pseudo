/*
 * Copyright (c) 2008-2010, 2013 Wind River Systems
 * Copyright (c) 2026 Yocto Project
 * see guts/COPYRIGHT for information.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * int openat2(int dirfd, const char *path, const struct open_how *how, size_t size)
 *	int rc = -1;
 */
	PSEUDO_STATBUF buf;
	int overly_magic_nonblocking = 0;
	int existed = 1;
	int save_errno;
	sigset_t local_saved_sigmask;
	struct open_how my_how;
	char *pseudo_path;
	const char *stat_path, *record_path;
	int stat_flags;

	/* Validate parameters */
	if (!how || size < sizeof(struct open_how)) {
		errno = EINVAL;
		return -1;
	}
	if (size > sizeof(struct open_how)) {
		errno = E2BIG;
		return -1;
	}

	/* This wrapper is not called with modified paths, therefore we have to handle this ourselves.
	   We can't use the standard mappings since the function needs relative paths to be preserved,
	   they can't be our usual absolute paths. An example difference:
	   openat2(AT_FDCWD, "/tmp/testdir/dir1/dir2/", {flags=O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_PATH|O_DIRECTORY, resolve=RESOLVE_BENEATH}, 24) = -1 EXDEV (Invalid cross-device link)
	   vs.
           openat2(AT_FDCWD, "dir1/dir2/", {flags=O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_PATH|O_DIRECTORY, resolve=RESOLVE_BENEATH}, 24) = 4
           FIXME - we don't handle chroot for relative paths
	*/
        pseudo_path = pseudo_root_path(__func__, __LINE__, dirfd, path, 0);
	if (path && path[0] == '/')
		/* If the path is absolute, we should account for a potential chroot */
	        path = pseudo_path;

	memcpy(&my_how, how, size);

	stat_path = record_path = pseudo_path;
	stat_flags = (my_how.flags & O_NOFOLLOW) ? AT_SYMLINK_NOFOLLOW : 0;
	/* An empty path is passed to the kernel, which only accepts it with
	 * O_EMPTYPATH, to reopen dirfd.  Look at and record dirfd instead.
	 */
	if (path && !*path) {
		stat_path = "";
		stat_flags |= AT_EMPTY_PATH;
		record_path = pseudo_root_path(__func__, __LINE__, dirfd,
			dirfd == AT_FDCWD ? "." : "", 0);
	}

	/* mask out mode bits appropriately */
	my_how.mode = my_how.mode & ~pseudo_umask;

#ifndef SYS_openat2
	if (dirfd != AT_FDCWD) {
		errno = ENOSYS;
		return -1;
	}
#endif

#ifdef PSEUDO_FORCE_ASYNC
	/* Yes, I'm aware that every Linux system I've seen has
	 * DSYNC and RSYNC being the same value as SYNC.
	 */

	my_how.flags &= ~(O_SYNC
#ifdef O_DIRECT
		| O_DIRECT
#endif
#ifdef O_DSYNC
		| O_DSYNC
#endif
#ifdef O_RSYNC
		| O_RSYNC
#endif
	);
#endif

#ifdef O_TMPFILE
	/* don't handle O_CREAT the same way if O_TMPFILE exists
	 * and is set.
	 */
	if ((my_how.flags & O_TMPFILE) == O_TMPFILE) {
		existed = 0;
	} else
#endif
	/* if a creation has been requested, check whether file exists */
	/* note "else" in #ifdef O_TMPFILE above */
	if (my_how.flags & O_CREAT) {
		save_errno = errno;
		rc = base_fstatat(dirfd, stat_path, &buf, stat_flags);
		existed = (rc != -1);
		if (!existed)
			pseudo_debug(PDBGF_FILE, "openat2_creat: %s -> 0%lld\n", pseudo_path, my_how.mode);
		errno = save_errno;
	}

	/* if a pipe is opened without O_NONBLOCK, for only reading or
	 * only writing, it can block forever. We need to do extra magic
	 * in that case...
	 */
	if (!(my_how.flags & O_NONBLOCK) && ((my_how.flags & (O_WRONLY | O_RDONLY | O_RDWR)) != O_RDWR)) {
		save_errno = errno;
		rc = base_fstatat(dirfd, stat_path, &buf, stat_flags);
		if (rc != -1 && S_ISFIFO(buf.st_mode)) {
			overly_magic_nonblocking = 1;
		}
	}

	/* this is a horrible special case and i do not know whether it will work */
	if (overly_magic_nonblocking) {
		pseudo_droplock();
		sigprocmask(SIG_SETMASK, &pseudo_saved_sigmask, &local_saved_sigmask);
	}
	/* because we are not actually root, secretly mask in 0600 to the
	 * underlying mode.  The ", 0" is because the only time mode matters
	 * is if a file is going to be created, in which case it's
	 * not a directory.
	 */
#ifndef SYS_openat2
	pseudo_debug(PDBGF_SYSCALL, "openat2, calling open.\n");
	rc = real_open(path, my_how.flags, PSEUDO_FS_MODE(my_how.mode, 0));
#else
	/* openat2 in glibc is still rare, so directly call the syscall if required */
	if (real_openat2) {
		pseudo_debug(PDBGF_SYSCALL, "openat2, calling openat2.\n");
		rc = real_openat2(dirfd, path, how, size);
	} else {
		pseudo_debug(PDBGF_SYSCALL, "openat2, calling syscall.\n");
		rc = real_syscall(SYS_openat2, dirfd, path, how, size);
	}
#endif
	if (overly_magic_nonblocking) {
		save_errno = errno;
		sigprocmask(SIG_SETMASK, &local_saved_sigmask, NULL);
		/* well this is a problem. we can't NOT proceed; we may have
		 * already opened the file! we can't even return up the call
		 * stack to stuff that's going to try to drop the lock.
		 */
		if (pseudo_getlock()) {
			pseudo_critical("PANIC: after opening a readonly/writeonly FIFO (path '%s', fd %d, errno %d, saved errno %d), could not regain lock. unrecoverable. sorry. bye.\n",
				pseudo_path, rc, errno, save_errno);
		}
		errno = save_errno;
	}

	if (rc != -1) {
		save_errno = errno;
		int stat_rc;
#ifdef O_TMPFILE
		/* in O_TMPFILE case, nothing gets put in the
		 * database, because there's no directory entries for
		 * the file yet.
		 */
		if ((my_how.flags & O_TMPFILE) == O_TMPFILE) {
			real_fchmod(rc, PSEUDO_FS_MODE(my_how.mode, 0));
			errno = save_errno;
			return rc;
		}
#endif
		stat_rc = base_fstatat(dirfd, stat_path, &buf, stat_flags);

		pseudo_debug(PDBGF_FILE, "openat2(path %s), flags %lld, stat rc %d, stat mode %o\n",
			pseudo_path, my_how.flags, stat_rc, buf.st_mode);
		if (stat_rc != -1) {
			buf.st_mode = PSEUDO_DB_MODE(buf.st_mode, my_how.mode);
			if (!existed) {
				int path_lock_fd = pseudo_client_path_lock(0);
				real_fchmod(rc, PSEUDO_FS_MODE(my_how.mode, 0));
				// file has no path, but has been created
				if (pseudo_client_path_matches_fd(pseudo_path, rc, my_how.flags & O_NOFOLLOW) &&
				    base_fstat(rc, &buf) != -1) {
					buf.st_mode = PSEUDO_DB_MODE(buf.st_mode, my_how.mode);
					pseudo_client_op(OP_CREAT, 0, -1, dirfd, pseudo_path, &buf);
				}
				pseudo_client_path_unlock(path_lock_fd);
			}
				pseudo_client_op(OP_OPEN, PSEUDO_ACCESS(my_how.flags), rc, dirfd, record_path, &buf);
		} else {
			pseudo_debug(PDBGF_FILE, "openat2 (fd %d, path %d/%s, flags %lld) succeeded, but stat failed (%s).\n",
				rc, dirfd, pseudo_path, my_how.flags, strerror(errno));
			pseudo_client_op(OP_OPEN, PSEUDO_ACCESS(my_how.flags), rc, dirfd, record_path, 0);
		}
		errno = save_errno;
	}

/*	return rc;
 * }
 */
