/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once
#include "goodix_tls.h"
/* fprintd's system state directory. Used when the process euid owns this
 * file, typically after a privileged local install. */
#define GOODIX_KEY_SYSTEM_PATH "/var/lib/fprint/goodix-55b4.psk"
#define GOODIX_KEY_STATE_LEAF "libfprint-goodix-55b4/goodix-55b4.psk"
#define GOODIX_WRAP_KEY_SIZE GOODIX_TLS_PSK_SIZE
#define GOODIX_KEY_WRAP_SYSTEM_PATH "/var/lib/fprint/goodix-55b4.wrap"
#define GOODIX_KEY_WRAP_STATE_LEAF "libfprint-goodix-55b4/goodix-55b4.wrap"

/* Read a caller-selected, owned, mode-0600 regular file without following a
 * final symlink. Never prints a path, key, hash, or file contents. */
bool goodix_key_read(const char *path, uint8_t key[GOODIX_TLS_PSK_SIZE]);

/* Resolve a PSK file without embedding a user home directory:
 * 1. GOODIX55B4_PSK_FILE, if it is an absolute path
 * 2. $XDG_STATE_HOME/libfprint-goodix-55b4/goodix-55b4.psk
 *    or ~/.local/state/libfprint-goodix-55b4/goodix-55b4.psk
 * 3. GOODIX_KEY_SYSTEM_PATH
 * Every candidate must still pass goodix_key_read. Missing files fall back
 * to the public community TLS key (all zeros) plus a device white-box write. */
bool goodix_key_load(uint8_t key[GOODIX_TLS_PSK_SIZE]);

/* AES-GCM wrap key for stored SIGFM templates (not a TLS PSK). Load order:
 * GOODIX55B4_WRAP_FILE, XDG/state leaf, then the system path. If none exist,
 * create GOODIX_KEY_WRAP_SYSTEM_PATH as a new 0600 file. */
bool goodix_key_load_or_create_wrap(uint8_t key[GOODIX_WRAP_KEY_SIZE]);
