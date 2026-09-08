/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include "goodix_key.h"
#include "goodix_security.h"
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
    char path[] = "/tmp/goodix-synthetic-key-XXXXXX";
    unsigned char input[GOODIX_TLS_PSK_SIZE] = {0}, output[GOODIX_TLS_PSK_SIZE];
    int fd = mkstemp(path);
    assert(fd >= 0);
    assert(write(fd, input, sizeof(input)) == sizeof(input));
    assert(goodix_key_read(path, output));
    assert(fchmod(fd, 0400) == 0);
    assert(!goodix_key_read(path, output));
    assert(fchmod(fd, 0640) == 0);
    assert(!goodix_key_read(path, output));
    assert(fchmod(fd, 0600) == 0);
    assert(write(fd, input, 1) == 1);
    assert(!goodix_key_read(path, output));
    assert(ftruncate(fd, sizeof(input)) == 0);
    assert(goodix_key_read(path, output));
    assert(!goodix_key_read("relative", output));
    char linkpath[sizeof(path) + 8];
    strcpy(linkpath, path);
    strcat(linkpath, ".link");
    assert(symlink(path, linkpath) == 0);
    assert(!goodix_key_read(linkpath, output));
    assert(unlink(linkpath) == 0);
    assert(close(fd) == 0);
    assert(unlink(path) == 0);
    assert(mkfifo(path, 0600) == 0);
    assert(!goodix_key_read(path, output));
    assert(unlink(path) == 0);
    assert(goodix_security_disable_dumps());
    assert(prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0);
    struct rlimit limit;
    assert(getrlimit(RLIMIT_CORE, &limit) == 0);
    assert(limit.rlim_cur == 0 && limit.rlim_max == 0);
}
