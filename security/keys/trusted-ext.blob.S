/* SPDX-License-Identifier: GPL-2.0 */
	.section .init.rodata, "a"
	.global keyhelper_umh_start
keyhelper_umh_start:
	.incbin "security/keys/keyhelper_umh"
	.global keyhelper_umh_end
keyhelper_umh_end:
