/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once
#include <stdbool.h>
#include <sys/resource.h>
#include <sys/prctl.h>

/* Process-wide by design: call before loading keys or collecting biometrics.
 * RLIMIT_CORE alone does not exclude Linux pipe-based crash collectors. */
static inline bool goodix_security_disable_dumps(void)
{
    const struct rlimit limit = {0, 0};
    return setrlimit(RLIMIT_CORE, &limit) == 0 &&
           prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0;
}

/* Research builds must opt in at compile time; environment variables cannot
 * turn a distributed default build into a biometric authenticator. */
#ifndef GOODIX55B4_DEVELOPMENT
#define GOODIX55B4_DEVELOPMENT 0
#endif
#ifndef GOODIX55B4_DEVELOPMENT_CAPTURE
#define GOODIX55B4_DEVELOPMENT_CAPTURE 0
#endif
