/*
 * pseudo.h, shared definitions and structures for pseudo
 *
 * Copyright (c) 2008-2010, 2013 Wind River Systems, Inc.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
#include <stdlib.h>
#include <fcntl.h>

/* List of magic initialization functions... */
extern void pseudo_init_wrappers(void);
extern void pseudo_init_util(void);
extern void pseudo_init_client(void);

void pseudo_dump_env(char **envp);
int pseudo_set_value(const char *key, const char *value);
char *pseudo_get_value(const char *key);
int pseudo_has_unload(char * const *envp);

#include "pseudo_tables.h"

extern void pseudo_debug_verbose(void);
extern void pseudo_debug_terse(void);
extern void pseudo_debug_set(char *);
extern void pseudo_debug_clear(char *);
extern void pseudo_debug_flags_finalize(void);
extern void pseudo_severity_set(char *);
extern void pseudo_severity_flags_finalize(void);
extern unsigned long pseudo_util_debug_flags;
extern unsigned long pseudo_util_evlog_flags;
extern unsigned long pseudo_util_severity_flags;
extern int pseudo_util_debug_fd;
extern int pseudo_util_evlog_fd;
extern int pseudo_disabled;
extern int pseudo_allow_fsync;
extern int pseudo_log(char *, ...) __attribute__ ((format (printf, 1, 2)));
extern int pseudo_evlog_internal(char *, ...) __attribute__ ((format (printf, 1, 2)));
#define pseudo_evlog(x, ...) do { \
	if (pseudo_util_evlog_flags & (x)) { pseudo_evlog_internal(__VA_ARGS__); } \
} while (0) 
extern void pseudo_evlog_dump(void);
#ifndef NDEBUG
#define pseudo_critical(fmt, ...) do { \
	pseudo_log("CRITICAL: " fmt, ##__VA_ARGS__); \
	abort(); \
} while (0)
#define pseudo_error(fmt, ...) do { \
	pseudo_log("ERROR: " fmt, ##__VA_ARGS__); \
} while (0)
#define pseudo_warning(fmt, ...) do { \
	if (pseudo_util_severity_flags & SEVERITYF_WARN) { \
		pseudo_log("WARNING: " fmt, ##__VA_ARGS__); \
	} \
} while (0)
#define pseudo_info(fmt, ...) do { \
	if (pseudo_util_severity_flags & SEVERITYF_INFO) { \
		pseudo_log("INFO: " fmt, ##__VA_ARGS__); \
	} \
} while (0)
#define pseudo_debug(x, ...) do { \
	if ((x) & PDBGF_VERBOSE) { \
		if ((pseudo_util_debug_flags & PDBGF_VERBOSE) && (pseudo_util_debug_flags & ((x) & ~PDBGF_VERBOSE))) { pseudo_log(__VA_ARGS__); } \
	} else { \
		if ((pseudo_util_debug_flags & (x)) || ((x) == 0)) { pseudo_log(__VA_ARGS__); } \
	} \
} while (0) 
#define pseudo_debug_call(x, fn, ...) do { \
	if ((x) & PDBGF_VERBOSE) { \
		if ((pseudo_util_debug_flags & PDBGF_VERBOSE) && (pseudo_util_debug_flags & ((x) & ~PDBGF_VERBOSE))) { fn(__VA_ARGS__); } \
	} else { \
		if (pseudo_util_debug_flags & (x)) { fn(__VA_ARGS__); } \
	} \
} while (0) 
#else
/* this used to be a static inline function, but that meant that arguments
 * were still evaluated for side effects. We don't want that. The ...
 * is a C99ism, also supported by GNU C.
 */
#define pseudo_debug(...) 0
#define pseudo_debug_call(...) 0
#endif
extern void pseudo_dump_data(char *, const void *, size_t);
void pseudo_new_pid(void);
/* pseudo_fix_path resolves symlinks up to this depth */
#define PSEUDO_MAX_LINK_RECURSION 16
extern char *pseudo_fix_path(const char *, const char *, size_t, size_t, size_t *, int);
extern void pseudo_dropenv(void);
extern char **pseudo_dropenvp(char **);
extern void pseudo_setupenv(void);
extern char **pseudo_setupenvp(char * const *);
extern void pseudo_free_envp(char **envp);
extern char *pseudo_prefix_path(char *);
extern char *pseudo_bindir_path(char *);
extern char *pseudo_libdir_path(char *);
extern char *pseudo_localstatedir_path(char *);
extern char *pseudo_get_prefix(char *);
extern char *pseudo_get_bindir(void);
extern char *pseudo_get_libdir(void);
extern char *pseudo_get_localstatedir(void);
extern int pseudo_debug_logfile(char *defname, int prefer_fd);
extern int pseudo_evlog_logfile(char *defname, int prefer_fd);
extern ssize_t pseudo_sys_path_max(void);
extern ssize_t pseudo_path_max(void);
#define PSEUDO_PWD_MAX 4096
extern int pseudo_etc_file(const char *filename, char *realname, int flags, const char **search_dirs, int dircount);

extern long pseudo_strtol_wrapper(const char *, char **, int);
extern long long pseudo_strtoll_wrapper(const char *, char **, int);
extern int pseudo_atoi_wrapper(const char *);

extern char *pseudo_version;

#ifndef PSEUDO_BINDIR
 #define PSEUDO_BINDIR "bin"
#endif

#ifndef PSEUDO_LIBDIR
 #define PSEUDO_LIBDIR "lib"
#endif

#define STARTSWITH(x, y) (strncmp(y, x, strlen(y)) == 0)

#ifndef PSEUDO_LOCALSTATEDIR
 #define PSEUDO_LOCALSTATEDIR "var/pseudo"
#endif

#define PSEUDO_LOCKFILE "pseudo.lock"
#define PSEUDO_LOGFILE "pseudo.log"
#define PSEUDO_PATHLOCK "pseudo.pathlock"
#define PSEUDO_PIDFILE "pseudo.pid"
#define PSEUDO_SOCKET "pseudo.socket"
#define PSEUDO_REQUEST_SOCKET "pseudo.request"

#define PSEUDO_SEVERITY_DEFAULT "info,warn,error"

/* pseudo defines operations in terms of each other; for instance,
 * open(...) is the same as openat(AT_FDCWD, ...).  This requires the *at()
 * functions and AT_FDCWD, AT_SYMLINK_NOFOLLOW and AT_SYMLINK_FOLLOW from
 * <fcntl.h>.
 */
#ifndef AT_FDCWD
#error "pseudo requires *at() function support (AT_FDCWD, AT_SYMLINK_NOFOLLOW, AT_SYMLINK_FOLLOW)"
#endif

/* Someone might not have O_LARGEFILE (the flag equivalent to
 * using open64()).  Since open64() is the same as O_LARGEFILE in flags,
 * we implement it that way... If the system has no O_LARGEFILE, we'll
 * just call open() with nothing special.
 */ 
#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

/* Does link(2) let you create hard links to symlinks? Of course not. Who
 * would ever do that? Well, Linux did, and possibly as a result, linkat()
 * does by default too; if you are on a host with the historical Unix
 * behavior of following symlinks to find the link target, you will want
 * to set this to AT_SYMLINK_FOLLOW.  0 means not following them; it can't
 * be AT_SYMLINK_NOFOLLOW, as linkat() rejects that flag.
 */
#define PSEUDO_LINK_SYMLINK_BEHAVIOR 0

/* given n, pick a multiple of block enough bigger than n
 * to give us some breathing room.
 */
static inline size_t
round_up(size_t n, size_t block) {
	return block * (((n + block / 4) / block) + 1);
}

#ifdef PSEUDO_PROFILING
typedef struct {
	int processes;
	long long total_ops;
	long long messages;
	struct timeval op_time;
	struct timeval ipc_time;
	struct timeval wrapper_time;
} pseudo_profile_t;
#endif
#include "pseudo_ports.h"

/* convert between struct stat and the port's PSEUDO_STATBUF */
extern void pseudo_stat32_from64(struct stat *, const PSEUDO_STATBUF *);
extern void pseudo_stat64_from32(PSEUDO_STATBUF *, const struct stat *);
