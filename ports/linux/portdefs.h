/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
#define PRELINK_LIBRARIES "LD_PRELOAD"
#define PRELINK_PATH "LD_LIBRARY_PATH"
#define PSEUDO_STATBUF struct stat64
/* How pseudo stats files itself, bypassing its own wrappers.  glibc's
 * stat64() and friends were inline wrappers around __xstat64() and
 * friends before glibc 2.33, and pseudo still uses those to work with
 * binaries built against older glibc.
 */
#define base_lstat real_lstat64
#define base_fstat real_fstat64
#define base_stat real_stat64
#define base_fstatat(dirfd, path, buf, flags) real___fxstatat64(_STAT_VER, dirfd, path, buf, flags)
#define PSEUDO_LINKPATH_SEPARATOR " "
/* There were symbol changes that can cause the linker to request
 * newer versions of glibc, which causes problems occasionally on
 * older hosts if pseudo is built against a newer glibc and then
 * run with an older one. Sometimes we can just avoid the symbols,
 * but memcpy's pretty hard to get away from.
 */
#define GLIBC_COMPAT_SYMBOL(sym, ver) __asm(".symver " #sym "," #sym "@GLIBC_" #ver)

#if defined(__amd64__) && !defined(__ILP32__)
GLIBC_COMPAT_SYMBOL(memcpy,2.2.5);
#elif defined(__i386__)
GLIBC_COMPAT_SYMBOL(memcpy,2.0);
#endif

#include <linux/capability.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <sys/mount.h>

/* close_range()'s flags, and unshare(), are only declared by glibc under
 * _GNU_SOURCE, which pseudo does not build with. <linux/close_range.h> is
 * not an option either: it is absent on hosts with pre-5.9 kernel headers,
 * the same problem SYS_openat2 has below. Both values are kernel ABI.
 */
#ifndef CLOSE_RANGE_UNSHARE
#define CLOSE_RANGE_UNSHARE (1U << 1)
#endif
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif
#ifndef CLONE_FILES
#define CLONE_FILES 0x00000400
#endif
extern int unshare(int flags);

#ifndef _STAT_VER
#if defined (__aarch64__) || defined (__riscv)
#define _STAT_VER 0
#elif defined (__x86_64__)
#define _STAT_VER 1
#else
#define _STAT_VER 3
#endif
#endif
#ifndef _MKNOD_VER
#if defined (__aarch64__) || defined(__riscv)
#define _MKNOD_VER 0
#elif defined (__x86_64__)
#define _MKNOD_VER 0
#else
#define _MKNOD_VER 1
#endif
#endif

/* Ubuntu 20.04, Debian 11 and Opensuse 15.5 need this */
#ifndef SYS_openat2

/* On kernel <5.6, __NR_openat2 is not defined. Import the definition from
 * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=fddb5d430ad9fa91b49b1d34d0202ffe2fa0e179
 */
#ifndef __NR_openat2
#define __NR_openat2 437
#endif

#define SYS_openat2 __NR_openat2
#endif

#ifndef SYS_open_tree

#ifndef __NR_open_tree
#define __NR_open_tree 428
#endif

#define SYS_open_tree __NR_open_tree
#endif

/* The new mount API is only in <sys/mount.h> from glibc 2.36, and
 * <linux/mount.h> is missing from older kernel headers (before 5.2), so
 * don't rely on either.  OPEN_TREE_CLONE is kernel ABI, and struct
 * mount_attr is only used through pointers, so it can stay incomplete.
 */
#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE (1U << 0)
#endif
struct mount_attr;

#ifndef SYS_open_tree_attr

#ifndef __NR_open_tree_attr
#define __NR_open_tree_attr 467
#endif

#define SYS_open_tree_attr __NR_open_tree_attr
#endif

#include "io_uring_syscalls.h"
