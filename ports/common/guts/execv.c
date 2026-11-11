/* 
 * Copyright (c) 2010 Wind River Systems; see
 * guts/COPYRIGHT for information.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * static int
 * wrap_execv(const char *file, char *const *argv) {
 *	int rc = -1;
 */
	char **new_environ, **orig_environ;

	/* note:  we don't canonicalize this, because we are intentionally
	 * NOT redirecting execs into the chroot environment.  If you try
	 * to execute /bin/sh, you get the actual /bin/sh, not
	 * <CHROOT>/bin/sh.  This allows use of basic utilities.  This
	 * design will likely be revisited.
	 */
	if (antimagic == 0) {
		const char *path_guess = pseudo_exec_path(file, 0);
                pseudo_client_op(OP_EXEC, PSA_EXEC, -1, -1, path_guess, 0);
	}

	/* Due to bash intercepting setenv/getenv/unsetenv and changing environ
	   internally itself at will, we create our own environ copy at process
	   creation based on it to ensure it is correct */
	orig_environ = environ;
	new_environ = pseudo_setupenvp(environ);
	if (pseudo_has_unload(new_environ))
		new_environ = pseudo_dropenvp(new_environ);
	environ = new_environ;

	/* if exec() fails, we may end up taking signals unexpectedly...
	 * not much we can do about that.
	 */
	/* exec() skips destructors, so collect errors for requests
	 * sent without waiting now
	 */
	pseudo_client_flush();
	sigprocmask(SIG_SETMASK, &pseudo_saved_sigmask, NULL);
	rc = real_execv(file, argv);

	environ = orig_environ;
	pseudo_free_envp(new_environ);

/*	return rc;
 * }
 */
