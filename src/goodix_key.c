/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include "goodix_key.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

bool goodix_key_read(const char *path, uint8_t key[GOODIX_TLS_PSK_SIZE])
{
    uint8_t buffer[GOODIX_TLS_PSK_SIZE + 1] = {0};
    struct stat st;
    size_t length = 0;
    bool ok = false;
    if (!key) return false;
    explicit_bzero(key, GOODIX_TLS_PSK_SIZE);
    if (!path || path[0] != '/') return false;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return false;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        (st.st_mode & 0777) != 0600 || st.st_uid != geteuid() ||
        st.st_size != GOODIX_TLS_PSK_SIZE) goto out;
    while (length < sizeof(buffer)) {
        ssize_t count = read(fd, buffer + length, sizeof(buffer) - length);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) goto out;
        if (count == 0) break;
        length += (size_t)count;
    }
    if (length == GOODIX_TLS_PSK_SIZE) {
        memcpy(key, buffer, GOODIX_TLS_PSK_SIZE); ok = true;
    }
out:
    explicit_bzero(buffer, sizeof(buffer));
    close(fd);
    return ok;
}

static bool
join_key_path(char *out, size_t out_size, const char *dir, const char *leaf)
{
    int written;

    if (out == NULL || dir == NULL || dir[0] != '/' || leaf == NULL)
        return false;
    written = snprintf(out, out_size, "%s/%s", dir, leaf);
    return written > 0 && (size_t)written < out_size;
}

/* Search order: an explicit absolute path from the environment, the XDG state
 * leaf (or ~/.local/state when XDG_STATE_HOME is unset), then the system path.
 * Every candidate must pass goodix_key_read. */
static bool
load_from_locations(uint8_t key[GOODIX_TLS_PSK_SIZE], const char *env_name,
                    const char *leaf, const char *system_path)
{
    char path[PATH_MAX];
    const char *env = secure_getenv(env_name);
    const char *state = secure_getenv("XDG_STATE_HOME");
    const char *home = secure_getenv("HOME");

    if (env != NULL && env[0] == '/')
        return goodix_key_read(env, key);
    if (state != NULL && state[0] == '/') {
        if (join_key_path(path, sizeof(path), state, leaf) &&
            goodix_key_read(path, key))
            return true;
    } else if (home != NULL && home[0] == '/') {
        int written = snprintf(path, sizeof(path), "%s/.local/state/%s", home, leaf);
        if (written > 0 && (size_t)written < sizeof(path) &&
            goodix_key_read(path, key))
            return true;
    }
    return goodix_key_read(system_path, key);
}

bool goodix_key_load(uint8_t key[GOODIX_TLS_PSK_SIZE])
{
    return load_from_locations(key, "GOODIX55B4_PSK_FILE",
                               GOODIX_KEY_STATE_LEAF, GOODIX_KEY_SYSTEM_PATH);
}

static bool
parent_allows_create(const char *path)
{
    char parent[PATH_MAX];
    struct stat st;
    size_t length;
    const char *slash;

    if (path == NULL || path[0] != '/')
        return false;
    slash = strrchr(path, '/');
    if (slash == NULL || slash == path)
        return false;
    length = (size_t)(slash - path);
    if (length >= sizeof(parent))
        return false;
    memcpy(parent, path, length);
    parent[length] = 0;
    if (lstat(parent, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 022) != 0)
        return false;
    return true;
}

static bool
create_wrap_key(const char *path, uint8_t key[GOODIX_WRAP_KEY_SIZE])
{
    uint8_t generated[GOODIX_WRAP_KEY_SIZE];
    int fd;
    size_t written = 0;

    explicit_bzero(key, GOODIX_WRAP_KEY_SIZE);
    if (!parent_allows_create(path))
        return false;
    if (getentropy(generated, sizeof(generated)) != 0) {
        explicit_bzero(generated, sizeof(generated));
        return false;
    }
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY,
              0600);
    if (fd < 0) {
        explicit_bzero(generated, sizeof(generated));
        return false;
    }
    if (fchmod(fd, 0600) != 0) {
        close(fd);
        unlink(path);
        explicit_bzero(generated, sizeof(generated));
        return false;
    }
    while (written < sizeof(generated)) {
        ssize_t count = write(fd, generated + written, sizeof(generated) - written);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            close(fd);
            unlink(path);
            explicit_bzero(generated, sizeof(generated));
            return false;
        }
        written += (size_t)count;
    }
    if (fsync(fd) != 0) {
        close(fd);
        unlink(path);
        explicit_bzero(generated, sizeof(generated));
        return false;
    }
    close(fd);
    memcpy(key, generated, sizeof(generated));
    explicit_bzero(generated, sizeof(generated));
    return true;
}

static bool
load_wrap_existing(uint8_t key[GOODIX_WRAP_KEY_SIZE])
{
    return load_from_locations(key, "GOODIX55B4_WRAP_FILE",
                               GOODIX_KEY_WRAP_STATE_LEAF,
                               GOODIX_KEY_WRAP_SYSTEM_PATH);
}

bool goodix_key_load_or_create_wrap(uint8_t key[GOODIX_WRAP_KEY_SIZE])
{
    if (load_wrap_existing(key))
        return true;
    if (create_wrap_key(GOODIX_KEY_WRAP_SYSTEM_PATH, key) &&
        goodix_key_read(GOODIX_KEY_WRAP_SYSTEM_PATH, key))
        return true;
    return load_wrap_existing(key);
}
