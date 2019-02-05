// SPDX-License-Identifier: GPL-2.0+

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>

#include "ext-keyprotocol.h"

#define _kregalign __attribute__((aligned(__alignof__(struct keyreq))))

static uint8_t buffer[UM_MESSAGE_SIZE] _kregalign;
static int dfd;

static void hexdump(char *token, uint8_t *data, int len)
{
	dprintf(dfd, "%s: ", token);
	for (int i = 0; i < len; i++)
		dprintf(dfd, "%02hhx:", data[i]);
	dprintf(dfd, "\n");
}

static int frob(uint8_t *data, size_t datalen)
{
	memfrob(data, datalen);
	return 0;
}

static int genkey(uint8_t *data, size_t datalen)
{
	ssize_t len;
	int fd;

	if (datalen <= 0)
		return -EINVAL;

	mknod("/dev/urandom", S_IFCHR|0666, makedev(1, 9));

	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1) {
		dprintf(dfd, "Open failed\n");
		return -EFAULT;
	}
	len = read(fd, data, datalen);
	close(fd);
	if (len != datalen) {
		dprintf(dfd, "Read failed, %lu expected %lu\n", len,
			datalen);
		return -EFAULT;
	}
	return 0;
}

int main(int a, char **b)
{
	struct keyreq *req = (struct keyreq *)buffer;
	size_t bytesin, bytesout;
	uint8_t *dp;

	dfd = open("/dev/console", O_WRONLY);
	dprintf(dfd, "Started keyhelper\n");

	while (1) {
		bytesin = read(0, buffer, UM_MESSAGE_SIZE);

		if (bytesin < sizeof(*req))
			continue;

		dp = buffer + sizeof(*req);
		hexdump("datain", dp, req->datalen);

		switch (req->request) {
		case UM_CREATE_KEY:
			dprintf(dfd, "%u byte key generation request\n",
				req->datalen);
			req->reply = genkey(dp, req->datalen);
			if (!req->reply)
				bytesin = req->datalen + sizeof(*req);
			break;
		case UM_SEAL_KEY:
			dprintf(dfd, "%u byte seal request\n",
				req->datalen);
			req->reply = frob(dp, req->datalen);
			break;
		case UM_UNSEAL_KEY:
			dprintf(dfd, "%u byte unseal request\n",
				req->datalen);
			req->reply = frob(dp, req->datalen);
			break;
		default:
			dprintf(dfd, "Unknown %lu byte message\n",
				bytesin);
			req->reply = -EINVAL;
			break;
		}

		hexdump("dataout", dp, req->datalen);

		bytesout = write(1, buffer, bytesin);
		if (bytesin < bytesout)
			dprintf(dfd, "Error writing reply\n");

		memset(buffer, 0, UM_MESSAGE_SIZE);
	}
	close(dfd);
	return 0;
}
