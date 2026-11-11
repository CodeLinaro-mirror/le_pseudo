/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * static int
 * wrap_execveat(int dirfd, const char *path, char *const *argv, char *const *envp, int flags) {
 *	int rc = -1;
 */
	char **new_environ;

	/* as for execve(), the path is not canonicalized or redirected
	 * into the chroot environment
	 */
	if (antimagic == 0 && path && (path[0] == '/' || dirfd == AT_FDCWD)) {
		const char *path_guess = pseudo_exec_path(path, 0);
		pseudo_client_op(OP_EXEC, PSA_EXEC, -1, -1, path_guess, 0);
	}

	new_environ = pseudo_setupenvp(envp);
	if (pseudo_has_unload(new_environ))
		new_environ = pseudo_dropenvp(new_environ);

	/* exec() skips destructors, so collect errors for requests
	 * sent without waiting now
	 */
	pseudo_client_flush();
	sigprocmask(SIG_SETMASK, &pseudo_saved_sigmask, NULL);
	rc = real_execveat(dirfd, path, argv, new_environ, flags);

	pseudo_free_envp(new_environ);

/*	return rc;
 * }
 */
