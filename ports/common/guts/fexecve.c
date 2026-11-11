/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * static int
 * wrap_fexecve(int fd, char *const *argv, char *const *envp) {
 *	int rc = -1;
 */
	char **new_environ;

	new_environ = pseudo_setupenvp(envp);
	if (pseudo_has_unload(new_environ))
		new_environ = pseudo_dropenvp(new_environ);

	/* exec() skips destructors, so collect errors for requests
	 * sent without waiting now
	 */
	pseudo_client_flush();
	sigprocmask(SIG_SETMASK, &pseudo_saved_sigmask, NULL);
	rc = real_fexecve(fd, argv, new_environ);

	pseudo_free_envp(new_environ);

/*	return rc;
 * }
 */
