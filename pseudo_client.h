/*
 * pseudo_client.h, shared declarations for client
 *
 * Copyright (c) 2008-2010 Wind River Systems, Inc.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
extern pseudo_msg_t *pseudo_client_op(pseudo_op_t op, int access, int fd, int dirfd, const char *path, const PSEUDO_STATBUF *buf, ...);
extern int pseudo_client_ignore_path(const char *path);
extern int pseudo_client_ignore_fd(int fd);
extern void pseudo_client_linked_paths(const char *oldpath, const char *newpath);
/* The port defines how pseudo stats files itself, on PSEUDO_STATBUF */
#if !defined(base_lstat) || !defined(base_fstat) || !defined(base_stat) || !defined(base_fstatat)
#error "pseudo: the port must define base_lstat, base_fstat, base_stat and base_fstatat"
#endif
extern void pseudo_antimagic(void);
extern void pseudo_magic(void);
extern void pseudo_client_touchuid(void);
extern void pseudo_client_touchgid(void);
extern int pseudo_client_shutdown(int);
extern void pseudo_client_flush(void);
extern int pseudo_client_flush_needed(void);
extern int pseudo_fd(int fd, int how);
extern int pseudo_client_path_lock(int shared);
extern void pseudo_client_path_unlock(int fd);
extern int pseudo_client_path_matches_fd(const char *path, int fd, int nofollow);
#define MOVE_FD	0
#define COPY_FD	1
#define PSEUDO_MIN_FD	20
extern uid_t pseudo_euid;
extern uid_t pseudo_fuid;
extern uid_t pseudo_suid;
extern uid_t pseudo_ruid;
extern gid_t pseudo_egid;
extern gid_t pseudo_sgid;
extern gid_t pseudo_rgid;
extern gid_t pseudo_fgid;
extern int pseudo_localstate_dir_fd;
extern FILE *pseudo_pwd_open(void);
extern FILE *pseudo_grp_open(void);
extern void pseudo_pwd_close(void);
extern void pseudo_grp_close(void);
extern int pseudo_pwd_lck_open(void);
extern int pseudo_pwd_lck_close(void);
extern FILE *pseudo_pwd;
extern FILE *pseudo_grp;

/* pseudo_wrappers will try to initialize these */
extern int (*pseudo_real_lstat)(const char *path, PSEUDO_STATBUF *buf);
extern int (*pseudo_real_fstat)(int fd, PSEUDO_STATBUF *buf);
extern int (*pseudo_real_stat)(const char *path, PSEUDO_STATBUF *buf);
extern int (*pseudo_real_fork)(void);
extern int (*pseudo_real_execv)(const char *, char * const *);

/* support related to chroot/getcwd/etc. */
extern int pseudo_client_getcwd(void);
extern int pseudo_client_chroot(const char *);
extern char *pseudo_root_path(const char *, int, int, const char *, int);
extern const char *pseudo_exec_path(const char *filename, int);
#define PSEUDO_ROOT_PATH(x, y, z) pseudo_root_path(__func__, __LINE__, (x), (y), (z));
extern char *pseudo_cwd;
extern size_t pseudo_cwd_len;
extern char *pseudo_cwd_rel;
extern char *pseudo_chroot;
extern char *pseudo_passwd;
extern size_t pseudo_chroot_len;
extern int pseudo_nosymlinkexp;

extern int pseudo_umask;

extern void readenv_uids(void);
extern void readenv_gids(void);
extern int read_pidfile(FILE *, int *);

/* Root can read and write files, and enter directories which have no
 * read, write, or execute permissions.  (But can't execute files without
 * execute permissions!)
 *
 * A non-root user can't.
 *
 * When doing anything which actually writes to the filesystem, we add in
 * the user read/write/execute bits.  When storing to the database, though,
 * we mask out any such bits which weren't in the original mode.
 *
 * Additional setuid/setgid modes are also filtered as they are unsafe as
 * a real executable may allow someone to setuid/gid as the running user.
 *
 * Note: PSEUDO_DB_MODE must be kept in sync with PSEUDO_FS_MODE, as the
 * former defined which filesystem mode bits must be loaded from the DB.
 *
 * Note: S_ISUID and S_ISGID may be stripped during a mkdir as a user,
 * account for this in PSEUDO_DB_MODE.
 */
#define PSEUDO_FS_MODE(mode, isdir) (((mode) | S_IRUSR | S_IWUSR | ((isdir) ? S_IXUSR : 0)) & ~(S_IWGRP | S_IWOTH | S_ISUID | S_ISGID))
#define PSEUDO_DB_MODE(fs_mode, user_mode) (((fs_mode) & ~(S_IRUSR | S_IWUSR | S_IXUSR | S_IWGRP | S_IWOTH | S_ISUID | S_ISGID)) | ((user_mode) & (S_IRUSR | S_IWUSR | S_IXUSR | S_IWGRP | S_IWOTH | S_ISUID | S_ISGID)))

