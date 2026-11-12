/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * io_uring syscall numbers.  Prefer the host/SDK sysroot definitions: pseudo
 * native and nativesdk builds may execute on different architectures.
 */
#ifndef PSEUDO_IO_URING_SYSCALLS_H
#define PSEUDO_IO_URING_SYSCALLS_H

#include <sys/syscall.h>

#ifndef SYS_io_uring_setup
# ifdef __NR_io_uring_setup
#  define SYS_io_uring_setup __NR_io_uring_setup
# endif
#endif
#ifndef SYS_io_uring_enter
# ifdef __NR_io_uring_enter
#  define SYS_io_uring_enter __NR_io_uring_enter
# endif
#endif
#ifndef SYS_io_uring_register
# ifdef __NR_io_uring_register
#  define SYS_io_uring_register __NR_io_uring_register
# endif
#endif

/* Linux headers older than 5.1 do not define the io_uring calls.  Supply
 * fallbacks only for ABIs whose assignments are known.  In particular, Alpha
 * has its own numbers, MIPS adds its ABI base, and x32 adds its syscall bit.
 */
#if !defined(SYS_io_uring_setup) || !defined(SYS_io_uring_enter) ||     !defined(SYS_io_uring_register)
# if defined(__alpha__)
#  define PSEUDO_NR_io_uring_setup 535
#  define PSEUDO_NR_io_uring_enter 536
#  define PSEUDO_NR_io_uring_register 537
# elif defined(__mips__) && defined(__NR_Linux)
#  define PSEUDO_NR_io_uring_setup (__NR_Linux + 425)
#  define PSEUDO_NR_io_uring_enter (__NR_Linux + 426)
#  define PSEUDO_NR_io_uring_register (__NR_Linux + 427)
# elif defined(__x86_64__) && defined(__ILP32__) &&        defined(__X32_SYSCALL_BIT)
#  define PSEUDO_NR_io_uring_setup (__X32_SYSCALL_BIT + 425)
#  define PSEUDO_NR_io_uring_enter (__X32_SYSCALL_BIT + 426)
#  define PSEUDO_NR_io_uring_register (__X32_SYSCALL_BIT + 427)
# elif defined(__i386__) ||        (defined(__x86_64__) && !defined(__ILP32__)) ||        defined(__arm__) || defined(__aarch64__) || defined(__riscv) ||        defined(__powerpc__) || defined(__s390__) || defined(__sparc__) ||        defined(__m68k__) || defined(__hppa__) || defined(__sh__) ||        defined(__loongarch__) || defined(__arc__) || defined(__csky__) ||        defined(__hexagon__) || defined(__microblaze__) ||        defined(__nios2__) || defined(__or1k__) || defined(__xtensa__)
#  define PSEUDO_NR_io_uring_setup 425
#  define PSEUDO_NR_io_uring_enter 426
#  define PSEUDO_NR_io_uring_register 427
# endif
#endif

#ifndef SYS_io_uring_setup
# ifdef PSEUDO_NR_io_uring_setup
#  define SYS_io_uring_setup PSEUDO_NR_io_uring_setup
# endif
#endif
#ifndef SYS_io_uring_enter
# ifdef PSEUDO_NR_io_uring_enter
#  define SYS_io_uring_enter PSEUDO_NR_io_uring_enter
# endif
#endif
#ifndef SYS_io_uring_register
# ifdef PSEUDO_NR_io_uring_register
#  define SYS_io_uring_register PSEUDO_NR_io_uring_register
# endif
#endif

#if defined(SYS_io_uring_setup) && defined(SYS_io_uring_enter) &&     defined(SYS_io_uring_register)
#define PSEUDO_HAVE_IO_URING_SYSCALLS 1
#endif

#endif
