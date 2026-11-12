/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Kernel-enforced io_uring refusal for pseudo.
 *
 * An LD_PRELOAD wrapper can only see callers which go through libc.  The two
 * most common io_uring users do not: liburing is normally built with
 * CONFIG_NOLIBC and emits syscall instructions of its own, and fio inlines a
 * syscall instruction on its submission path.  Those callers reach the kernel
 * directly, which means they hold a real ring and can create, rename or
 * unlink files without pseudo recording any of it - and wrong ownership baked
 * into an image is far harder to notice than a failure would have been.
 *
 * There is nothing to wrap, either: glibc exports no io_uring entry point at
 * all, so the kernel is the only place the question can be answered.  A
 * seccomp filter marks io_uring_setup(), io_uring_enter() and
 * io_uring_register() and answers them with ENOSYS, which is what a kernel
 * built without io_uring says and what every caller worth worrying about
 * already has a fallback for.  The filter is inherited across fork() and
 * execve(), so one installation covers an entire build, including the
 * processes libpseudo cannot be loaded into.
 *
 * Two modes, chosen by environment variable: deny (the default) and
 * passthrough.  See the mode enum below.  The mode only
 * decides whether the filter is installed; pseudo's syscall() wrapper refuses
 * io_uring for callers which go through libc either way.
 *
 * no_new_privs is a precondition for installing a filter without privilege,
 * and this never sets it: doing so would suppress setuid and file
 * capabilities for the process and everything it execs, which in a build
 * stops a sysroot's own setuid helpers working, and that is not a decision
 * pseudo should make on an application's behalf.  Where it is unset and
 * pseudo is unprivileged, no filter can be installed, and callers which make
 * the system call themselves are not refused.
 *
 * The mode in force, and anything which went wrong installing the filter,
 * are reported only in the debug output (PSEUDO_DEBUG=c).  pseudo is preloaded
 * into every process a build runs, and none of this stops pseudo working, so
 * it must not end up in the output of programs whose output is captured.
 */

#include <stddef.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2
#endif
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC (1UL << 0)
#endif
#ifndef SECCOMP_FILTER_FLAG_LOG
#define SECCOMP_FILTER_FLAG_LOG (1UL << 1)
#endif
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW 0x7fff0000U
#endif
#ifndef SECCOMP_RET_ERRNO
#define SECCOMP_RET_ERRNO 0x00050000U
#endif
#ifndef SECCOMP_RET_DATA
#define SECCOMP_RET_DATA 0x0000ffffU
#endif
#ifndef PR_GET_NO_NEW_PRIVS
#define PR_GET_NO_NEW_PRIVS 39
#endif

/* AUDIT_ARCH_* for the ABI this copy of libpseudo was built for.  There is no
 * value meaning "whatever this is", so the ABI still has to be named, but the
 * number behind the name comes from the sysroot: one table fewer to keep
 * right, and a new architecture is two lines rather than a constant to look
 * up and get wrong.
 *
 * A sysroot without <linux/audit.h>, or with one too old to name this ABI,
 * leaves PSEUDO_SECCOMP_AUDIT_ARCH undefined - as does an architecture missing
 * below - and then no filter is installed and io_uring reaches the kernel on
 * it unexamined.
 *
 * Endianness does not come into it, which is worth saying because the
 * constants suggest it should.  <linux/audit.h> defines AUDIT_ARCH_ARMEB
 * beside AUDIT_ARCH_ARM, but nothing in the kernel ever answers with it:
 * arch/arm's syscall_get_arch() returns AUDIT_ARCH_ARM for every arm task -
 * "ARM tasks don't change audit architectures on the fly" - and its
 * SECCOMP_ARCH_NATIVE is that same value, while an arm task under an aarch64
 * kernel is reported as AUDIT_ARCH_ARM as well.  aarch64 has the one value
 * for both endiannesses too.  So a big-endian build matches on the same
 * constant as a little-endian one, and there is nothing to exclude.
 */
#if !defined(__has_include) || __has_include(<linux/audit.h>)
#include <linux/audit.h>
#endif

#if defined(__x86_64__) && !defined(__ILP32__) && defined(AUDIT_ARCH_X86_64)
#define PSEUDO_SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__i386__) && defined(AUDIT_ARCH_I386)
#define PSEUDO_SECCOMP_AUDIT_ARCH AUDIT_ARCH_I386
#elif defined(__aarch64__) && defined(AUDIT_ARCH_AARCH64)
#define PSEUDO_SECCOMP_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__arm__) && defined(AUDIT_ARCH_ARM)
#define PSEUDO_SECCOMP_AUDIT_ARCH AUDIT_ARCH_ARM
#elif defined(__riscv) && __riscv_xlen == 64 && defined(AUDIT_ARCH_RISCV64)
#define PSEUDO_SECCOMP_AUDIT_ARCH AUDIT_ARCH_RISCV64
#endif

/* The variable which picks the mode, and the marker pseudo carries in its
 * own environment.  The marker stops the thousands of processes in
 * a build each stacking another copy, since every filter in the chain is
 * evaluated on every syscall the process makes.  pseudo re-exports its own
 * variables across exec, including for callers that build their own
 * environment, so these survive where a plain setenv() would not.
 */
#define PSEUDO_IO_URING_MODE_VAR "PSEUDO_IO_URING_SECCOMP"
#define PSEUDO_IO_URING_FILTER_MARKER "PSEUDO_IO_URING_FILTER"

/* How this process treats io_uring.
 *
 * Deny is the default.  A build does not need io_uring; it needs pseudo to see
 * the file operations.  Refusing the syscalls outright costs a caller the
 * fallback path it already has, and costs pseudo nothing.
 *
 *   PSEUDO_IO_URING_SECCOMP=0   passthrough: no filter is installed, so
 *                               callers which make the system call
 *                               themselves get a working io_uring, and
 *                               pseudo does not see what they do with it.
 *   PSEUDO_IO_URING_SECCOMP=1   deny, and the default: io_uring_setup()
 *                               answers ENOSYS and callers take the fallback
 *                               they already have.
 *
 * The values are the numbers the variable is set to, so that a mode can be
 * added without renumbering the ones already documented.
 */
enum pseudo_io_uring_mode {
	PSEUDO_IO_URING_MODE_PASSTHROUGH = 0,
	PSEUDO_IO_URING_MODE_DENY = 1,
	PSEUDO_IO_URING_MODE_LAST = PSEUDO_IO_URING_MODE_DENY
};

#ifdef PSEUDO_SECCOMP_AUDIT_ARCH
static const char *
pseudo_io_uring_mode_name(enum pseudo_io_uring_mode mode)
{
	switch (mode) {
	case PSEUDO_IO_URING_MODE_PASSTHROUGH:
		return "passthrough";
	default:
		return "deny";
	}
}

/* The mode asked for by the environment, or by the value pseudo carried
 * across an exec for a caller which built its own environment.
 */
static enum pseudo_io_uring_mode
pseudo_io_uring_wanted_mode(void)
{
	enum pseudo_io_uring_mode mode = PSEUDO_IO_URING_MODE_DENY;
	char *env = getenv(PSEUDO_IO_URING_MODE_VAR);
	char *owned = NULL;
	char *end;
	long value;

	if (env)
		pseudo_set_value(PSEUDO_IO_URING_MODE_VAR, env);
	else
		env = owned = pseudo_get_value(PSEUDO_IO_URING_MODE_VAR);
	if (!env)
		return mode;

	value = strtol(env, &end, 10);
	if (end != env && !*end && value >= 0 &&
	    value <= PSEUDO_IO_URING_MODE_LAST) {
		mode = (enum pseudo_io_uring_mode) value;
	} else {
		/* Worth saying, because the mode which was asked for is not
		 * the mode which is in force. */
		pseudo_debug(PDBGF_CLIENT, "io_uring: %s=%s is not a mode; using %s\n",
			PSEUDO_IO_URING_MODE_VAR, env,
			pseudo_io_uring_mode_name(mode));
	}
	free(owned);
	return mode;
}

/* Has some ancestor already installed the filter?  Asking the kernel would
 * mean issuing an io_uring syscall, which is fatal under an unrelated filter
 * whose action is SECCOMP_RET_KILL, so the answer is carried in pseudo's own
 * environment instead.
 */
static int
pseudo_io_uring_filter_present(void)
{
	char *env = getenv(PSEUDO_IO_URING_FILTER_MARKER);
	int present;

	if (env) {
		pseudo_set_value(PSEUDO_IO_URING_FILTER_MARKER, env);
		return 1;
	}
	env = pseudo_get_value(PSEUDO_IO_URING_FILTER_MARKER);
	present = env != NULL;
	free(env);
	return present;
}

/* Why a filter could not be installed, almost always.
 *
 * Installing one requires either privilege or no_new_privs, and this never
 * sets the latter: it suppresses setuid and file capabilities for the process
 * and everything it execs, which in a build stops a sysroot's own setuid
 * helpers working, and that is not a decision pseudo should make on an
 * application's behalf.  So where it is unset and pseudo is unprivileged,
 * deny cannot be enforced and says so. */
static int
pseudo_io_uring_no_new_privs(void)
{
	return real_prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1;
}

/* The three syscalls, answered with ENOSYS in the kernel, so nothing about
 * io_uring reaches this process at all: io_uring_setup() fails the way it does
 * on a kernel built without it.
 */
static int
pseudo_io_uring_install_filter(void)
{
	struct sock_filter filter[] = {
		/* Only the native ABI is decoded below, so anything else is
		 * left to the kernel. */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PSEUDO_SECCOMP_AUDIT_ARCH, 0, 4),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_io_uring_setup, 3, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_io_uring_enter, 2, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_io_uring_register, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K,
			SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)),
	};
	struct sock_fprog prog = {
		.len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};

	/* real_syscall, because pseudo's own wrappers answer seccomp requests
	 * with a polite lie so that applications cannot sandbox away the
	 * wrappers they are supposed to be using. */
#ifdef SYS_seccomp
	/* What to ask for, in descending order of preference.
	 *
	 * TSYNC applies the filter to every thread in the process, which is
	 * what the marker recorded on success is a claim about.  LOG has the
	 * kernel record each refusal where an operator can find it - the audit
	 * log, or the kernel ring buffer where nothing is listening to audit -
	 * and changes nothing about what the filter does.
	 *
	 * Neither is insisted on, because a sandbox can implement seccomp
	 * without implementing every flag of it: gVisor answers EINVAL to LOG,
	 * with or without TSYNC beside it, as does a kernel older than 4.14.
	 * Refusing to install over that would trade the thing which denies
	 * io_uring for a flag which only describes it, so a rejected flag is
	 * dropped and the filter goes in anyway.  TSYNC is given up last of
	 * the two, being a property of the filter rather than of the record of
	 * it.
	 *
	 * Where TSYNC is given up, the call can also fail by answering with a
	 * sibling thread's id rather than -1, which is why only zero is taken
	 * for success.  What is installed then covers this thread and whatever
	 * it goes on to create, and not that sibling or the children the
	 * sibling execs - which will find the marker and decide they need no
	 * filter of their own.  Partial coverage recorded as whole-process
	 * coverage, in other words, and it is left that way because the path
	 * is not reachable the way pseudo is loaded: the constructor runs
	 * before main() in the single thread a process starts with, so there
	 * is no sibling to disagree.  Getting there takes libpseudo dlopen'd
	 * into a running process whose threads have sandboxed themselves
	 * apart, and the thread which asked is still better off filtered than
	 * not.
	 */
	static const unsigned long flag_sets[] = {
		SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_LOG,
		SECCOMP_FILTER_FLAG_TSYNC,
		SECCOMP_FILTER_FLAG_LOG,
		0
	};
	unsigned int i;

	for (i = 0; i < sizeof(flag_sets) / sizeof(flag_sets[0]); ++i) {
		if (real_syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
		    flag_sets[i], &prog) == 0)
			return 0;
	}
#endif
	/* Kernels without seccomp(2) have no flags to ask for at all, so this
	 * one is per-thread and unlogged whatever the circumstances. */
	return real_prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
}
#endif /* PSEUDO_SECCOMP_AUDIT_ARCH */

/* Called from _libpseudo_init(), so: once per process, after the real_*
 * pointers and the client are set up, and again in every process that execs.
 */
static void
pseudo_io_uring_init(void)
{
#ifdef PSEUDO_SECCOMP_AUDIT_ARCH
	static int done = 0;
	enum pseudo_io_uring_mode mode;

	if (done)
		return;
	done = 1;

	/* PSEUDO_DISABLED means "stay out of the way", which is the same
	 * answer as asking for passthrough. */
	if (pseudo_disabled)
		return;

	mode = pseudo_io_uring_wanted_mode();

	if (mode == PSEUDO_IO_URING_MODE_PASSTHROUGH) {
		/* Nothing installed and nothing asked of the kernel, so there
		 * is nothing to report but the choice itself. */
		if (pseudo_io_uring_filter_present())
			/* An ancestor's filter cannot be removed, so the
			 * request cannot be honoured: io_uring stays refused.
			 * Worth saying, because the caller asked for one thing
			 * and is getting another. */
			pseudo_debug(PDBGF_CLIENT, "io_uring: passthrough requested but a filter is inherited; io_uring calls will fail with ENOSYS\n");
		else
			pseudo_debug(PDBGF_CLIENT, "io_uring: passthrough (io_uring calls made without syscall() are not refused)\n");
		return;
	}

	/* Already in force for this whole process tree, and a second copy
	 * would only cost every syscall the process makes. */
	if (pseudo_io_uring_filter_present()) {
		pseudo_debug(PDBGF_CLIENT, "io_uring: deny (filter inherited)\n");
		return;
	}

	if (pseudo_io_uring_install_filter() < 0) {
		int save_errno = errno;

		/* Nearly always the precondition rather than anything
		 * exotic, so it is named: a filter can be installed either
		 * with privilege or with no_new_privs, and pseudo has neither
		 * to offer. */
		pseudo_debug(PDBGF_CLIENT, "io_uring: deny requested but no filter could be installed (%s%s); io_uring calls made without syscall() will go unrecorded\n",
			strerror(save_errno),
			pseudo_io_uring_no_new_privs() ? "" :
				"; no_new_privs is unset");
		return;
	}
	pseudo_set_value(PSEUDO_IO_URING_FILTER_MARKER, "1");
	pseudo_debug(PDBGF_CLIENT, "io_uring: deny\n");
#endif
}
