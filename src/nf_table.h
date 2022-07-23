/*
 * Copyright (c) 2022 Dmitry Dolenko
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */

#ifndef NF_TABLE_H
#define NF_TABLE_H

#include <stdint.h>
#include <pthread.h>

#include "nf_flow.h"

#define NR_BUCKETS 1024 * 1024 /* Number of buckets, pow of 2 */

typedef uint32_t (*hash_func_t)(const void *key, const size_t length);

typedef struct bucket_entry {
    struct bucket_entry *next;
    nf_flow_t flow;
} bucket_entry_t;

typedef struct bucket_head {
    bucket_entry_t *head;
} bucket_head_t;

typedef struct nf_table {
    bucket_head_t buckets[NR_BUCKETS];
    pthread_mutex_t bkt_mutexes[NR_BUCKETS];

    size_t size; /* current number of flows in all buckets */

    hash_func_t hash_func;
} nf_table_t;

void nf_table_init(nf_table_t **nft, hash_func_t hash_func);
void nf_table_free(nf_table_t **nft);
int nf_table_add(nf_table_t *nft, nf_flow_spec_t flow_spec);
int nf_table_remove(nf_table_t *nft, nf_flow_spec_t flow_spec);

#endif /* NF_TABLE_H */
