/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
/* the unix port wants to know that real_stat() and
 * friends exist.  So they do. And because the Linux
 * port really uses stat64 for those...
 */
int
pseudo_stat(const char *path, struct stat *buf) {
	return real___xstat(_STAT_VER, path, buf);
}

int
pseudo_lstat(const char *path, struct stat *buf) {
	return real___lxstat(_STAT_VER, path, buf);
}

int
pseudo_fstat(int fd, struct stat *buf) {
	return real___fxstat(_STAT_VER, fd, buf);
}

int
pseudo_stat64(const char *path, struct stat64 *buf) {
	return real___xstat64(_STAT_VER, path, buf);
}

int
pseudo_lstat64(const char *path, struct stat64 *buf) {
	return real___lxstat64(_STAT_VER, path, buf);
}

int
pseudo_fstat64(int fd, struct stat64 *buf) {
	return real___fxstat64(_STAT_VER, fd, buf);
}

/* similar thing happens with mknod */
int
pseudo_mknod(const char *path, mode_t mode, dev_t dev) {
	return real___xmknod(_MKNOD_VER, path, mode, &dev);
}

int
pseudo_mknodat(int dirfd, const char *path, mode_t mode, dev_t dev) {
	return real___xmknodat(_MKNOD_VER, dirfd, path, mode, &dev);
}

/* The host's is_selinux_enabled() and is_selinux_mls_enabled(), used only
 * while pseudo is disabled.  They are in libselinux, which may not be loaded
 * when the wrappers are set up, or at all, so look them up when they are
 * needed.  Without libselinux, SELinux isn't in use.
 */
int
pseudo_is_selinux_enabled(void) {
	static int (*f)(void) = NULL;

	if (!f)
		f = (int (*)(void)) dlsym(RTLD_NEXT, "is_selinux_enabled");
	return f ? f() : 0;
}

int
pseudo_is_selinux_mls_enabled(void) {
	static int (*f)(void) = NULL;

	if (!f)
		f = (int (*)(void)) dlsym(RTLD_NEXT, "is_selinux_mls_enabled");
	return f ? f() : 0;
}

int pseudo_capset(cap_user_header_t hdrp, const cap_user_data_t datap) {
	(void)hdrp;
	(void)datap;

	return 0;
}

/* open_by_handle_at() emulation.
 *
 * The kernel only decodes a file handle for a caller with
 * CAP_DAC_READ_SEARCH, which a pseudo "root" doesn't have, so search
 * below mount_fd for the file instead.  name_to_handle_at() needs no
 * privilege, so a file matches if it encodes to the same handle.
 */
/* include/linux/exportfs.h */
#define PSEUDO_FILEID_USER_FLAGS 0xffff0000U
#define PSEUDO_FILEID_IS_CONNECTABLE 0x10000
#define PSEUDO_FILEID_IS_DIR 0x20000
#define PSEUDO_FILEID_VALID_USER_FLAGS (PSEUDO_FILEID_IS_CONNECTABLE | PSEUDO_FILEID_IS_DIR)
#ifndef AT_HANDLE_CONNECTABLE
#define AT_HANDLE_CONNECTABLE 0x002
#endif

/* nftw() has no context argument */
static struct {
	const struct file_handle *handle;
	int encode_flags;
	char *path;
	PSEUDO_STATBUF st;
} pseudo_handle_search;

static int
pseudo_handle_search_visit(const char *path, const struct stat64 *sb, int typeflag, struct FTW *ftw) {
	union {
		struct file_handle fh;
		char space[sizeof(struct file_handle) + MAX_HANDLE_SZ];
	} h;
	int mount_id;

	(void) ftw;
	if (typeflag == FTW_NS)
		return 0;
	h.fh.handle_bytes = MAX_HANDLE_SZ;
	if (real_name_to_handle_at(AT_FDCWD, path, &h.fh, &mount_id, pseudo_handle_search.encode_flags) == -1 ||
	    h.fh.handle_type != pseudo_handle_search.handle->handle_type ||
	    h.fh.handle_bytes != pseudo_handle_search.handle->handle_bytes ||
	    memcmp(h.fh.f_handle, pseudo_handle_search.handle->f_handle, h.fh.handle_bytes))
		return 0;
	pseudo_handle_search.path = strdup(path);
	pseudo_handle_search.st = *sb;
	return 1;
}

/* Check the arguments as the kernel does (fs/fhandle.c), then find and
 * open the file.
 */
static int
pseudo_open_by_handle(int mount_fd, const struct file_handle *handle, int flags) {
	char *root = NULL;
	char procpath[32];
	PSEUDO_STATBUF st;
	ssize_t len;
	int fd = -1;

	if (!handle) {
		errno = EFAULT;
		return -1;
	}
	if (handle->handle_bytes == 0 || handle->handle_bytes > MAX_HANDLE_SZ ||
	    handle->handle_type < 0 ||
	    ((unsigned int) handle->handle_type & PSEUDO_FILEID_USER_FLAGS & ~PSEUDO_FILEID_VALID_USER_FLAGS)) {
		errno = EINVAL;
		return -1;
	}
	if (mount_fd < 0 && mount_fd != AT_FDCWD) {
		errno = EBADF;
		return -1;
	}
	if (base_fstatat(mount_fd, "", &st, AT_EMPTY_PATH) == -1)
		return -1;

	root = malloc(pseudo_path_max());
	if (!root)
		return -1;
	if (mount_fd == AT_FDCWD) {
		if (!real_getcwd(root, pseudo_path_max()))
			goto out;
	} else {
		snprintf(procpath, sizeof(procpath), "/proc/self/fd/%d", mount_fd);
		len = real_readlink(procpath, root, pseudo_path_max() - 1);
		if (len <= 0 || root[0] != '/') {
			errno = ESTALE;
			goto out;
		}
		root[len] = '\0';
	}

	memset(&pseudo_handle_search, 0, sizeof(pseudo_handle_search));
	pseudo_handle_search.handle = handle;
	pseudo_handle_search.encode_flags = (handle->handle_type & PSEUDO_FILEID_IS_CONNECTABLE) ? AT_HANDLE_CONNECTABLE : 0;
	real_nftw64(root, pseudo_handle_search_visit, 16, FTW_PHYS | FTW_MOUNT);
	if (!pseudo_handle_search.path) {
		errno = ESTALE;
		goto out;
	}

	/* as the kernel, a symlink is only opened with O_PATH */
	fd = real_openat(AT_FDCWD, pseudo_handle_search.path, (flags & ~(O_CREAT | O_EXCL)) | O_NOFOLLOW);
	/* the path could have been replaced since it was checked */
	if (fd != -1 && (base_fstat(fd, &st) == -1 ||
	    st.st_dev != pseudo_handle_search.st.st_dev || st.st_ino != pseudo_handle_search.st.st_ino)) {
		real_close(fd);
		fd = -1;
		errno = ESTALE;
	}
	free(pseudo_handle_search.path);
	pseudo_handle_search.path = NULL;
out:
	free(root);
	return fd;
}

#ifdef PSEUDO_HAVE_IO_URING_SYSCALLS
#include "pseudo_io_uring_seccomp.c"
#endif

long
syscall(long number, ...) {
	long rc = -1;
	va_list ap;

	/* Reached before real_syscall is resolved: the caller may be a malloc
	 * implementation initializing itself, and pseudo_check_wrappers()
	 * would run _libpseudo_init() -> pseudo_init_util(), which allocates.
	 * Forward the numbers pseudo never rewrites without running that path.
	 *
	 * The !real_syscall half of the guard covers a narrower window than
	 * !_libpseudo_initted alone would: _libpseudo_init() (below) sets
	 * _libpseudo_initted before it resolves real_syscall via
	 * pseudo_init_wrappers(), so an allocator whose first touch happens
	 * from inside the constructor itself - rather than before it runs -
	 * would otherwise still fall through to pseudo_enosys() below. */
	if ((!_libpseudo_initted || !real_syscall) && number != SYS_openat2
#ifdef SYS_renameat2
	    && number != SYS_renameat2
#endif
#ifdef SYS_seccomp
	    && number != SYS_seccomp
#endif
#ifdef SYS_landlock_create_ruleset
	    && number != SYS_landlock_create_ruleset
	    && number != SYS_landlock_add_rule
	    && number != SYS_landlock_restrict_self
#endif
#ifdef SYS_io_uring_setup
	    && number != SYS_io_uring_setup
	    && number != SYS_io_uring_enter
	    && number != SYS_io_uring_register
#endif
	    ) {
		if (!real_syscall)
			real_syscall = (long (*)(long, ...)) dlsym(RTLD_NEXT, "syscall");
		if (real_syscall)
			goto call_syscall;
	}

	if (!pseudo_check_wrappers() || !real_syscall) {
		/* rc was initialized to the "failure" value */
		pseudo_enosys("syscall");
		return rc;
	}

#ifdef SYS_seccomp
	/* pseudo and seccomp are incompatible as pseudo uses different syscalls
	 * so pretend to enable seccomp but really do nothing */
	if (number == SYS_seccomp) {
		pseudo_debug(PDBGF_SYSCALL, "syscall, faking seccomp.\n");
		unsigned long cmd;
		va_start(ap, number);
		cmd = va_arg(ap, unsigned long);
		va_end(ap);
		if (cmd == SECCOMP_SET_MODE_STRICT || cmd == SECCOMP_SET_MODE_FILTER) {
		    return 0;
		}
	}
#endif

        if (pseudo_disabled) {
                goto call_syscall;
        }

#ifdef SYS_landlock_create_ruleset
	/* A Landlock sandbox also binds libpseudo, which then can't reach the
	 * server (YOCTO #16493), so report Landlock as unsupported.
	 */
	if (number == SYS_landlock_create_ruleset ||
	    number == SYS_landlock_add_rule ||
	    number == SYS_landlock_restrict_self) {
		pseudo_debug(PDBGF_SYSCALL, "syscall, refusing landlock.\n");
		errno = ENOSYS;
		return -1;
	}
#endif

#ifdef SYS_io_uring_setup
	/* Operations submitted through an io_uring never pass through
	 * libpseudo, so files they create or change aren't tracked
	 * (YOCTO #15244).  Report io_uring as unsupported, as a kernel
	 * without it does, so callers fall back to ordinary calls.
	 */
	if (number == SYS_io_uring_setup ||
	    number == SYS_io_uring_enter ||
	    number == SYS_io_uring_register) {
		pseudo_debug(PDBGF_SYSCALL, "syscall, refusing io_uring.\n");
		errno = ENOSYS;
		return -1;
	}
#endif

#ifdef SYS_openat2
	/* There is a CVE patch (CVE-2025-45582) to tar 1.34 in Centos Stream which
	 * uses syscall to access openat2() and breaks builds if we don't redirect.
	 */
	if (number == SYS_openat2) {
		pseudo_debug(PDBGF_SYSCALL, "syscall, faking openat2.\n");
		va_start(ap, number);
		int dirfd = va_arg(ap, int);
		const char * path = va_arg(ap, const char *);
		void *how = va_arg(ap, void *);
		size_t size = va_arg(ap, size_t);

		return wrap_openat2(dirfd, path, how, size);
	}
#else
#error SYS_openat2 not defined
#endif

#ifdef SYS_open_tree
	if (number == SYS_open_tree) {
		pseudo_debug(PDBGF_SYSCALL, "syscall, faking open_tree.\n");
		va_start(ap, number);
		int dirfd = va_arg(ap, int);
		const char *path = va_arg(ap, const char*);
		unsigned int flags = va_arg(ap, unsigned int);

		return wrap_open_tree(dirfd, path, flags);
	}
#else
#error SYS_open_tree not defined
#endif

#ifdef SYS_open_tree_attr
	if (number == SYS_open_tree_attr) {
		pseudo_debug(PDBGF_SYSCALL, "syscall, faking open_tree_attr.\n");
		va_start(ap, number);
		int dirfd = va_arg(ap, int);
		const char *path = va_arg(ap, const char*);
		unsigned int flags = va_arg(ap, unsigned int);
		struct mount_attr *attr = va_arg(ap, struct mount_attr*);
		size_t size = va_arg(ap, size_t);

		return wrap_open_tree_attr(dirfd, path, flags, attr, size);
	}
#else
#error SYS_open_tree_attr not defined
#endif

#ifdef SYS_name_to_handle_at
	if (number == SYS_name_to_handle_at) {
		pseudo_debug(PDBGF_SYSCALL, "syscall, faking name_to_handle_at.\n");
		va_start(ap, number);
		int dirfd = va_arg(ap, int);
		const char *name = va_arg(ap, const char *);
		struct file_handle *handle = va_arg(ap, struct file_handle *);
		int *mount_id = va_arg(ap, int *);
		int flags = va_arg(ap, int);

		return wrap_name_to_handle_at(dirfd, name, handle, mount_id, flags);
	}
#else
#error SYS_name_to_handle_at not defined
#endif

#ifdef SYS_open_by_handle_at
	if (number == SYS_open_by_handle_at) {
		pseudo_debug(PDBGF_SYSCALL, "syscall, faking open_by_handle_at.\n");
		va_start(ap, number);
		int mount_fd = va_arg(ap, int);
		struct file_handle *handle = va_arg(ap, struct file_handle *);
		int flags = va_arg(ap, int);

		return wrap_open_by_handle_at(mount_fd, handle, flags);
	}
#else
#error SYS_open_by_handle_at not defined
#endif

#ifdef SYS_renameat2
        /* Call out wrapper, expanding the variable arguments first */
	if (number == SYS_renameat2) {
		pseudo_debug(PDBGF_SYSCALL, "syscall, faking renameat2.\n");
		va_start(ap, number);
		int olddirfd = va_arg(ap, int);
		const char * oldpath = va_arg(ap, const char *);
		int newdirfd = va_arg(ap, int);
		const char * newpath = va_arg(ap, const char *);
		unsigned int flags = va_arg(ap, unsigned int);

		return wrap_renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
	}
#endif

call_syscall:
	/* On Debian 11 - gcc (Debian 10.2.1-6) this results in:
	 *   error: a label can only be part of a statement and a declaration
	 *   is not a statement
	 *
	 * adding a ; here resolves this
	 */
	;

	/* gcc magic to attempt to just pass these args to syscall. we have to
	 * guess about the number of args; the docs discuss calling conventions
	 * up to 7, so let's try that?
	 */
	void *res = __builtin_apply((void (*)(void)) real_syscall, __builtin_apply_args(), sizeof(long) * 7);
	__builtin_return(res);
}

/* unused.
 */
static long wrap_syscall(long nr, va_list ap) {
	(void) nr;
	(void) ap;
	return -1;
}

int
prctl(int option, ...) {
	int rc = -1;
	va_list ap;

	/* See syscall() above: covers both the pre-constructor window and the
	 * mid-constructor one, for every option except the one prctl() itself
	 * still special-cases below. */
	if ((!_libpseudo_initted || !real_prctl)
#ifdef PR_SET_SECCOMP
	    && option != PR_SET_SECCOMP
#endif
	    ) {
		if (!real_prctl)
			real_prctl = (int (*)(int, ...)) dlsym(RTLD_NEXT, "prctl");
		if (real_prctl)
			goto call_prctl;
	}

	if (!pseudo_check_wrappers() || !real_prctl) {
		/* rc was initialized to the "failure" value */
		pseudo_enosys("prctl");
		return rc;
	}

#ifdef PR_SET_SECCOMP
	/* pseudo and seccomp are incompatible as pseudo uses different syscalls
	 * so pretend to enable seccomp but really do nothing.  prctl() takes
	 * SECCOMP_MODE_*, not the SECCOMP_SET_MODE_* values seccomp() takes.
	 */
	if (option == PR_SET_SECCOMP) {
		unsigned long cmd;
		va_start(ap, option);
		cmd = va_arg(ap, unsigned long);
		va_end(ap);
		if (cmd == SECCOMP_MODE_STRICT || cmd == SECCOMP_MODE_FILTER) {
		    pseudo_debug(PDBGF_SYSCALL, "prctl, faking seccomp.\n");
		    return 0;
		}
	}
#endif

call_prctl:
	/* On Debian 11 - gcc (Debian 10.2.1-6) this results in:
	 *   error: a label can only be part of a statement and a declaration
	 *   is not a statement
	 *
	 * adding a ; here resolves this
	 */
	;

	/* gcc magic to attempt to just pass these args to prctl. we have to
	 * guess about the number of args; the docs discuss calling conventions
	 * up to 5, so let's try that?
	 */
	void *res = __builtin_apply((void (*)(void)) real_prctl, __builtin_apply_args(), sizeof(long) * 5);
	__builtin_return(res);
}

/* unused.
 */
static int wrap_prctl(int option, va_list ap) {
	(void) option;
	(void) ap;
	return -1;
}

#undef NFTW_NAME
#undef NFTW_STAT_NAME
#undef NFTW_STAT_STRUCT
#undef NFTW_LSTAT_NAME
#define NFTW_NAME nftw64
#define NFTW_STAT_NAME stat64
#define NFTW_STAT_STRUCT stat64
#define NFTW_LSTAT_NAME lstat64
#include "../unix/guts/nftw_wrapper_base.c"
