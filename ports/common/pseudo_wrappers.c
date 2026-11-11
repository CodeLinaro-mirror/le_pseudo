/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

/* these aren't used, but the wrapper table isn't happy unless they
 * exist
 */
static int
wrap_execl(const char *file, const char *arg, va_list ap) {
	(void) file;
	(void) arg;
	(void) ap;
	return 0; 
}

static int
wrap_execle(const char *file, const char *arg, va_list ap) {
	(void) file;
	(void) arg;
	(void) ap;
	return 0;
}

static int
wrap_execlp(const char *file, const char *arg, va_list ap) {
	(void) file;
	(void) arg;
	(void) ap;
	return 0;
}

static char **
execl_to_v(va_list ap, const char *argv0, char *const **envp) {
	size_t i = 0;
	size_t alloc_size = 256;

	char **argv = malloc((sizeof *argv) * alloc_size);

	if (!argv) {
		pseudo_debug(PDBGF_CLIENT, "execl failed: couldn't allocate memory for %lu arguments\n",
			(unsigned long) alloc_size);
		return NULL;
	}
	argv[i++] = (char *) argv0;

	while (argv[i-1]) {
		argv[i++] = va_arg(ap, char *const);
		if (i > alloc_size - 1) {
			alloc_size = alloc_size + 256;
			argv = realloc(argv, (sizeof *argv) * alloc_size);
			if (!argv) {
				pseudo_debug(PDBGF_CLIENT, "execl failed: couldn't allocate memory for %lu arguments\n",
					(unsigned long) alloc_size);
				return NULL;
			}
		}
	}
	if (envp) {
		*envp = va_arg(ap, char **);
	}
	return argv;
}

/* The following wrappers require Special Handling */

int
execl(const char *file, const char *arg, ...) {
	sigset_t saved;
	va_list ap;
	char **argv;

	int rc = -1;

	PROFILE_START;

	if (!pseudo_check_wrappers()) {
		/* rc was initialized to the "failure" value */
		pseudo_enosys("execl");
		PROFILE_DONE;
		return rc;
	}

	va_start(ap, arg);
	argv = execl_to_v(ap, arg, 0);
	va_end(ap);
	if (!argv) {
		errno = ENOMEM;
		PROFILE_DONE;
		return -1;
	}

	pseudo_debug(PDBGF_WRAPPER, "called: execl\n");
	pseudo_sigblock(&saved);
	if (pseudo_getlock()) {
		errno = EBUSY;
		sigprocmask(SIG_SETMASK, &saved, NULL);
		PROFILE_DONE;
		return -1;
	}

	int save_errno;

	/* exec*() use this to restore the sig mask */
	pseudo_saved_sigmask = saved;
	rc = wrap_execv(file, argv);

	save_errno = errno;
	pseudo_droplock();
	sigprocmask(SIG_SETMASK, &saved, NULL);
	pseudo_debug(PDBGF_WRAPPER, "completed: execl\n");
	errno = save_errno;
	free(argv);
	PROFILE_DONE;
	return rc;
}

int
execlp(const char *file, const char *arg, ...) {
	sigset_t saved;
	va_list ap;
	char **argv;

	int rc = -1;
	PROFILE_START;

	if (!pseudo_check_wrappers()) {
		/* rc was initialized to the "failure" value */
		pseudo_enosys("execlp");
		PROFILE_DONE;
		return rc;
	}

	va_start(ap, arg);
	argv = execl_to_v(ap, arg, 0);
	va_end(ap);
	if (!argv) {
		errno = ENOMEM;
		PROFILE_DONE;
		return -1;
	}

	pseudo_debug(PDBGF_WRAPPER, "called: execlp\n");
	pseudo_sigblock(&saved);
	if (pseudo_getlock()) {
		errno = EBUSY;
		sigprocmask(SIG_SETMASK, &saved, NULL);
		PROFILE_DONE;
		return -1;
	}

	int save_errno;

	/* exec*() use this to restore the sig mask */
	pseudo_saved_sigmask = saved;
	rc = wrap_execvp(file, argv);

	save_errno = errno;
	pseudo_droplock();
	sigprocmask(SIG_SETMASK, &saved, NULL);
	pseudo_debug(PDBGF_WRAPPER, "completed: execlp\n");
	errno = save_errno;
	free(argv);
	PROFILE_DONE;
	return rc;
}

int
execle(const char *file, const char *arg, ...) {
	sigset_t saved;
	va_list ap;
	char **argv;
	char **envp;

	int rc = -1;
	PROFILE_START;

	if (!pseudo_check_wrappers()) {
		/* rc was initialized to the "failure" value */
		pseudo_enosys("execle");
		PROFILE_DONE;
		return rc;
	}

	va_start(ap, arg);
	argv = execl_to_v(ap, arg, (char *const **)&envp);
	va_end(ap);
	if (!argv) {
		errno = ENOMEM;
		PROFILE_DONE;
		return -1;
	}

	pseudo_debug(PDBGF_WRAPPER, "called: execle\n");
	pseudo_sigblock(&saved);
	if (pseudo_getlock()) {
		errno = EBUSY;
		sigprocmask(SIG_SETMASK, &saved, NULL);
		PROFILE_DONE;
		return -1;
	}

	int save_errno;

	/* exec*() use this to restore the sig mask */
	pseudo_saved_sigmask = saved;
	rc = wrap_execve(file, argv, envp);

	save_errno = errno;
	pseudo_droplock();
	sigprocmask(SIG_SETMASK, &saved, NULL);
	pseudo_debug(PDBGF_WRAPPER, "completed: execle\n");
	errno = save_errno;
	free(argv);
	PROFILE_DONE;
	return rc;
}

int
execv(const char *file, char *const *argv) {
	sigset_t saved;
	
	int rc = -1;

	PROFILE_START;

	if (!pseudo_check_wrappers() || !real_execv) {
		/* rc was initialized to the "failure" value */
		pseudo_enosys("execv");
		PROFILE_DONE;
		return rc;
	}

	pseudo_debug(PDBGF_WRAPPER, "called: execv\n");
	pseudo_sigblock(&saved);
	if (pseudo_getlock()) {
		errno = EBUSY;
		sigprocmask(SIG_SETMASK, &saved, NULL);
		PROFILE_DONE;
		return -1;
	}

	int save_errno;
			
	/* exec*() use this to restore the sig mask */
	pseudo_saved_sigmask = saved;
	rc = wrap_execv(file, argv);
		
	save_errno = errno;
	pseudo_droplock();
	sigprocmask(SIG_SETMASK, &saved, NULL);
	pseudo_debug(PDBGF_WRAPPER, "completed: execv\n");
	errno = save_errno;
	PROFILE_DONE;
	return rc;
}

int
execve(const char *file, char *const *argv, char *const *envp) {
	sigset_t saved;
	
	int rc = -1;
	PROFILE_START;

	if (!pseudo_check_wrappers() || !real_execve) {
		/* rc was initialized to the "failure" value */
		pseudo_enosys("execve");
		PROFILE_DONE;
		return rc;
	}

	pseudo_debug(PDBGF_WRAPPER, "called: execve\n");
	pseudo_sigblock(&saved);
	if (pseudo_getlock()) {
		errno = EBUSY;
		sigprocmask(SIG_SETMASK, &saved, NULL);
		PROFILE_DONE;
		return -1;
	}

	int save_errno;
			
	/* exec*() use this to restore the sig mask */
	pseudo_saved_sigmask = saved;
	rc = wrap_execve(file, argv, envp);
		
	save_errno = errno;
	pseudo_droplock();
	sigprocmask(SIG_SETMASK, &saved, NULL);
	pseudo_debug(PDBGF_WRAPPER, "completed: execve\n");
	errno = save_errno;
	PROFILE_DONE;
	return rc;
}

int
execvp(const char *file, char *const *argv) {
	sigset_t saved;
	
	int rc = -1;
	PROFILE_START;

	if (!pseudo_check_wrappers() || !real_execvp) {
		/* rc was initialized to the "failure" value */
		pseudo_enosys("execvp");
		PROFILE_DONE;
		return rc;
	}

	pseudo_debug(PDBGF_WRAPPER, "called: execvp\n");
	pseudo_sigblock(&saved);
	if (pseudo_getlock()) {
		errno = EBUSY;
		sigprocmask(SIG_SETMASK, &saved, NULL);
		PROFILE_DONE;
		return -1;
	}

	int save_errno;
			
	/* exec*() use this to restore the sig mask */
	pseudo_saved_sigmask = saved;
	rc = wrap_execvp(file, argv);
		
	save_errno = errno;
	pseudo_droplock();
	sigprocmask(SIG_SETMASK, &saved, NULL);
	pseudo_debug(PDBGF_WRAPPER, "completed: execvp\n");
	errno = save_errno;
	PROFILE_DONE;
	return rc;
}

int
execvpe(const char *file, char *const *argv, char *const *envp) {
	sigset_t saved;

	int rc = -1;
	PROFILE_START;

	if (!pseudo_check_wrappers() || !real_execvpe) {
		/* rc was initialized to the "failure" value */
		pseudo_enosys("execvpe");
		PROFILE_DONE;
		return rc;
	}

	pseudo_debug(PDBGF_WRAPPER, "called: execvpe\n");
	pseudo_sigblock(&saved);
	if (pseudo_getlock()) {
		errno = EBUSY;
		sigprocmask(SIG_SETMASK, &saved, NULL);
		PROFILE_DONE;
		return -1;
	}

	int save_errno;

	/* exec*() use this to restore the sig mask */
	pseudo_saved_sigmask = saved;
	rc = wrap_execvpe(file, argv, envp);

	save_errno = errno;
	pseudo_droplock();
	sigprocmask(SIG_SETMASK, &saved, NULL);
	pseudo_debug(PDBGF_WRAPPER, "completed: execvpe\n");
	errno = save_errno;
	PROFILE_DONE;
	return rc;
}

int
fexecve(int fd, char *const *argv, char *const *envp) {
	sigset_t saved;

	int rc = -1;
	PROFILE_START;

	if (!pseudo_check_wrappers() || !real_fexecve) {
		/* rc was initialized to the "failure" value */
		pseudo_enosys("fexecve");
		PROFILE_DONE;
		return rc;
	}

	pseudo_debug(PDBGF_WRAPPER, "called: fexecve\n");
	pseudo_sigblock(&saved);
	if (pseudo_getlock()) {
		errno = EBUSY;
		sigprocmask(SIG_SETMASK, &saved, NULL);
		PROFILE_DONE;
		return -1;
	}

	int save_errno;

	/* exec*() use this to restore the sig mask */
	pseudo_saved_sigmask = saved;
	rc = wrap_fexecve(fd, argv, envp);

	save_errno = errno;
	pseudo_droplock();
	sigprocmask(SIG_SETMASK, &saved, NULL);
	pseudo_debug(PDBGF_WRAPPER, "completed: fexecve\n");
	errno = save_errno;
	PROFILE_DONE;
	return rc;
}

int
execveat(int dirfd, const char *path, char *const *argv, char *const *envp, int flags) {
	sigset_t saved;

	int rc = -1;
	PROFILE_START;

	if (!pseudo_check_wrappers() || !real_execveat) {
		/* rc was initialized to the "failure" value */
		pseudo_enosys("execveat");
		PROFILE_DONE;
		return rc;
	}

	pseudo_debug(PDBGF_WRAPPER, "called: execveat\n");
	pseudo_sigblock(&saved);
	if (pseudo_getlock()) {
		errno = EBUSY;
		sigprocmask(SIG_SETMASK, &saved, NULL);
		PROFILE_DONE;
		return -1;
	}

	int save_errno;

	/* exec*() use this to restore the sig mask */
	pseudo_saved_sigmask = saved;
	rc = wrap_execveat(dirfd, path, argv, envp, flags);

	save_errno = errno;
	pseudo_droplock();
	sigprocmask(SIG_SETMASK, &saved, NULL);
	pseudo_debug(PDBGF_WRAPPER, "completed: execveat\n");
	errno = save_errno;
	PROFILE_DONE;
	return rc;
}

/* _exit() skips destructors, so collect errors for requests sent
 * without waiting here instead.
 */
void
_exit(int status) {
	pseudo_exit_flush();
	if (real__exit)
		real__exit(status);
	syscall(SYS_exit_group, status);
	for (;;)
		;
}

/* _Exit() is equivalent to _exit(), and glibc makes it a weak alias of
 * _exit, but callers bind to it by name, so it must be exported as well.
 */
void _Exit(int status) __attribute__((alias("_exit"), noreturn));

/* no profiling in fork because it wouldn't work anyway
 * half the time
 */
int
fork(void) {
	sigset_t saved;
	
	int rc = -1;

	if (!pseudo_check_wrappers() || !real_fork) {
		/* rc was initialized to the "failure" value */
		pseudo_enosys("fork");
		return rc;
	}

	pseudo_debug(PDBGF_WRAPPER, "called: fork\n");
	pseudo_sigblock(&saved);
	if (pseudo_getlock()) {
		errno = EBUSY;
		sigprocmask(SIG_SETMASK, &saved, NULL);
		return -1;
	}

	int save_errno;
			
	rc = wrap_fork();

	save_errno = errno;
		
	pseudo_droplock();
	sigprocmask(SIG_SETMASK, &saved, NULL);
	pseudo_debug(PDBGF_WRAPPER, "completed: fork\n");
	errno = save_errno;
	return rc;
}

int
vfork(void) {
	/* we don't provide support for the distinct semantics
	 * of vfork()
	 */
	return fork();
}

static int
wrap_execv(const char *file, char *const *argv) {
	int rc = -1;

#include "guts/execv.c"

	return rc;
}

static int
wrap_execve(const char *file, char *const *argv, char *const *envp) {
	int rc = -1;

#include "guts/execve.c"

	return rc;
}

static int
wrap_execvp(const char *file, char *const *argv) {
	int rc = -1;

#include "guts/execvp.c"

	return rc;
}

static int
wrap_execvpe(const char *file, char *const *argv, char *const *envp) {
	int rc = -1;

#include "guts/execvpe.c"

	return rc;
}

static int
wrap_fexecve(int fd, char *const *argv, char *const *envp) {
	int rc = -1;

#include "guts/fexecve.c"

	return rc;
}

static int
wrap_execveat(int dirfd, const char *path, char *const *argv, char *const *envp, int flags) {
	int rc = -1;

#include "guts/execveat.c"

	return rc;
}

/* not used, the hand-written wrappers flush and exit directly */
static void
wrap__exit(int status) {
	(void) status;
}

static int
wrap_fork(void) {
	int rc = -1;
	
#include "guts/fork.c"

	return rc;
}


int
posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const *argv, char *const *envp) {
	sigset_t saved;

	int rc = -1;
	PROFILE_START;

	if (!pseudo_check_wrappers() || !real_posix_spawn) {
		/* rc was initialized to the "failure" value */
		pseudo_enosys("posix_spawn");
		PROFILE_DONE;
		return rc;
	}

	pseudo_debug(PDBGF_WRAPPER, "called: posix_spawn\n");
	pseudo_sigblock(&saved);
	if (pseudo_getlock()) {
		errno = EBUSY;
		sigprocmask(SIG_SETMASK, &saved, NULL);
		PROFILE_DONE;
		return -1;
	}

	int save_errno;

	/* exec*() use this to restore the sig mask */
	pseudo_saved_sigmask = saved;
	rc = wrap_posix_spawn(pid, path, file_actions, attrp, argv, envp);

	save_errno = errno;
	pseudo_droplock();
	sigprocmask(SIG_SETMASK, &saved, NULL);
	pseudo_debug(PDBGF_WRAPPER, "completed: posix_spawn\n");
	errno = save_errno;
	PROFILE_DONE;
	return rc;
}

int
posix_spawnp(pid_t *pid, const char *file, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const *argv, char *const *envp) {
	sigset_t saved;

	int rc = -1;
	PROFILE_START;

	if (!pseudo_check_wrappers() || !real_posix_spawnp) {
		/* rc was initialized to the "failure" value */
		pseudo_enosys("posix_spawn");
		PROFILE_DONE;
		return rc;
	}

	pseudo_debug(PDBGF_WRAPPER, "called: posix_spawnp\n");
	pseudo_sigblock(&saved);
	if (pseudo_getlock()) {
		errno = EBUSY;
		sigprocmask(SIG_SETMASK, &saved, NULL);
		PROFILE_DONE;
		return -1;
	}

	int save_errno;

	/* exec*() use this to restore the sig mask */
	pseudo_saved_sigmask = saved;
	rc = wrap_posix_spawnp(pid, file, file_actions, attrp, argv, envp);

	save_errno = errno;
	pseudo_droplock();
	sigprocmask(SIG_SETMASK, &saved, NULL);
	pseudo_debug(PDBGF_WRAPPER, "completed: posix_spawnp\n");
	errno = save_errno;
	PROFILE_DONE;
	return rc;
}


static int
wrap_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const *argv, char *const *envp) {
	int rc = -1;

#include "guts/posix_spawn.c"

	return rc;
}

static int
wrap_posix_spawnp(pid_t *pid, const char *file, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const *argv, char *const *envp) {
	int rc = -1;

#include "guts/posix_spawnp.c"

	return rc;
}
