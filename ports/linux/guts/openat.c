/* 
 * Copyright (c) 2008-2010, 2013 Wind River Systems; see
 * guts/COPYRIGHT for information.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * static int
 * wrap_openat(int dirfd, const char *path, int flags, ...mode_t mode) {
 *	int rc = -1;
 */
	PSEUDO_STATBUF buf;
	int overly_magic_nonblocking = 0;
	int existed = 1;
	int save_errno;
	sigset_t local_saved_sigmask;
	const char *record_path = path;
	int stat_flags = (flags & O_NOFOLLOW) ? AT_SYMLINK_NOFOLLOW : 0;

	/* An empty path is left for the kernel, which only accepts it with
	 * O_EMPTYPATH, to reopen dirfd.  Look at and record dirfd instead.
	 */
	if (path && !*path) {
		stat_flags |= AT_EMPTY_PATH;
		record_path = pseudo_root_path(__func__, __LINE__, dirfd,
			dirfd == AT_FDCWD ? "." : "", 0);
	}

	/* mask out mode bits appropriately */
	mode = mode & ~pseudo_umask;

#ifdef PSEUDO_FORCE_ASYNC
        /* Yes, I'm aware that every Linux system I've seen has
         * DSYNC and RSYNC being the same value as SYNC.
         */

        flags &= ~(O_SYNC
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
	if ((flags & O_TMPFILE) == O_TMPFILE) {
		existed = 0;
	} else
#endif
	/* if a creation has been requested, check whether file exists */
	/* note "else" in #ifdef O_TMPFILE above */
	if (flags & O_CREAT) {
		save_errno = errno;
		rc = base_fstatat(dirfd, path, &buf, stat_flags);
		existed = (rc != -1);
		if (!existed)
			pseudo_debug(PDBGF_FILE, "openat_creat: %s -> 0%o\n", path, mode);
		errno = save_errno;
	}

	/* if a pipe is opened without O_NONBLOCK, for only reading or
	 * only writing, it can block forever. We need to do extra magic
	 * in that case...
	 */
	if (!(flags & O_NONBLOCK) && ((flags & (O_WRONLY | O_RDONLY | O_RDWR)) != O_RDWR)) {
		save_errno = errno;
		rc = base_fstatat(dirfd, path, &buf, stat_flags);
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
	rc = real_openat(dirfd, path, flags, PSEUDO_FS_MODE(mode, 0));
	if (overly_magic_nonblocking) {
		save_errno = errno;
		sigprocmask(SIG_SETMASK, &local_saved_sigmask, NULL);
		/* well this is a problem. we can't NOT proceed; we may have
		 * already opened the file! we can't even return up the call
		 * stack to stuff that's going to try to drop the lock.
		 */
		if (pseudo_getlock()) {
			pseudo_critical("after opening a readonly/writeonly FIFO (path '%s', fd %d, errno %d, saved errno %d), could not regain lock. unrecoverable. sorry. bye.\n",
				path, rc, errno, save_errno);
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
		if ((flags & O_TMPFILE) == O_TMPFILE) {
			real_fchmod(rc, PSEUDO_FS_MODE(mode, 0));
			errno = save_errno;
			return rc;
		}
#endif
		stat_rc = base_fstatat(dirfd, path, &buf, stat_flags);

		pseudo_debug(PDBGF_FILE, "openat(path %s), flags %o, stat rc %d, stat mode %o\n",
			path, flags, stat_rc, buf.st_mode);
		if (stat_rc != -1) {
			buf.st_mode = PSEUDO_DB_MODE(buf.st_mode, mode);
			if (!existed) {
				int path_lock_fd = pseudo_client_path_lock(0);
				real_fchmod(rc, PSEUDO_FS_MODE(mode, 0));
				// file has no path, but has been created
				if (pseudo_client_path_matches_fd(path, rc, flags & O_NOFOLLOW) &&
				    base_fstat(rc, &buf) != -1) {
					buf.st_mode = PSEUDO_DB_MODE(buf.st_mode, mode);
					pseudo_client_op(OP_CREAT, 0, -1, dirfd, path, &buf);
				}
				pseudo_client_path_unlock(path_lock_fd);
			}
				pseudo_client_op(OP_OPEN, PSEUDO_ACCESS(flags), rc, dirfd, record_path, &buf);
		} else {
			pseudo_debug(PDBGF_FILE, "openat (fd %d, path %d/%s, flags %d) succeeded, but stat failed (%s).\n",
				rc, dirfd, path, flags, strerror(errno));
			pseudo_client_op(OP_OPEN, PSEUDO_ACCESS(flags), rc, dirfd, record_path, 0);
		}
		errno = save_errno;
	}

/*	return rc;
 * }
 */
