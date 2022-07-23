/*
 * Copyright (c) 2022 Dmitry Dolenko
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */

#ifndef HASH_FUNCTIONS_H
#define HASH_FUNCTIONS_H

#include <stdlib.h>
#include <stdint.h>

typedef uint32_t (*hash_func_t)(const void *key, const size_t length);

enum hash_type {
    LOOKUP3_HASH = 1,
    MURMUR3_HASH = 2,
};

void hash_func_init(hash_func_t *func, enum hash_type type);

#endif /* HASH_FUNCTIONS_H */
