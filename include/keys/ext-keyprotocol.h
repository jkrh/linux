/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef __KERNEL__
#include <errno.h>
#endif

#define UM_MESSAGE_SIZE 4096

#define UM_NOMSG        0x00000000
#define UM_ECHO         0x00000001
#define UM_AUTH         0x00000002
#define UM_CREATE_KEY   0x00010001
#define UM_SEAL_KEY     0x00010002
#define UM_UNSEAL_KEY   0x00010003

struct keyreq {
	uint32_t request;
	int32_t  reply;
	uint32_t keytype;
	uint32_t keyhandle;
	uint32_t datalen;
};
