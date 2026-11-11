/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * static int
 * wrap_execvpe(const char *file, char *const *argv, char *const *envp) {
 *	int rc = -1;
 */
	char **new_environ;

	/* as for execvp(), the file is not canonicalized or redirected
	 * into the chroot environment
	 */
	if (antimagic == 0) {
		const char *path_guess = pseudo_exec_path(file, 1);
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
	rc = real_execvpe(file, argv, new_environ);

	pseudo_free_envp(new_environ);

/*	return rc;
 * }
 */
