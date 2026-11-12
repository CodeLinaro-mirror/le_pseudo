/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * A stand-in for libselinux which reports SELinux as enabled, so that
 * test-selinux-disabled can emulate a host where it is.
 */
int
is_selinux_enabled(void) {
	return 1;
}

int
is_selinux_mls_enabled(void) {
	return 1;
}
