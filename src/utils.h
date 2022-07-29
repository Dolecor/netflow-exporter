/*
 * Copyright (c) 2022 Dmitry Dolenko
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <sys/time.h>

inline uint32_t timeval_to_msec(struct timeval t)
{
    return t.tv_sec * 1000 + t.tv_usec / 1000;
}

#endif /* UTILS_H */
