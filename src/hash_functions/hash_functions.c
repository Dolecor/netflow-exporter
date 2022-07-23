/*
 * Copyright (c) 2022 Dmitry Dolenko
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */

#include "hash_functions/hash_functions.h"

#include <stdlib.h>
#include <stdio.h>

#include "hash_functions/lookup3/lookup3.h"
#include "hash_functions/murmur3/murmur3.h"

#define SEED 1234

uint32_t lookup3_wrapper(const void *key, const size_t length)
{
    return hashlittle(key, length, SEED);
}

uint32_t murmur3_wrapper(const void *key, const size_t length)
{
    uint32_t out;
    MurmurHash3_x86_32(key, length, SEED, &out);
    
    return out;
}

void hash_func_init(hash_func_t *func, enum hash_type type)
{
    switch (type) {
    case LOOKUP3_HASH:
        *func = lookup3_wrapper;
        break;
    case MURMUR3_HASH:
        *func = murmur3_wrapper;
        break;
    default:
        fprintf(stderr, "Invalid type of hash function\n");
        exit(EXIT_FAILURE);
    }
}