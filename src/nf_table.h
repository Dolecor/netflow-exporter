/*
 * Copyright (c) 2022 Dmitry Dolenko
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */

#ifndef NF_TABLE_H
#define NF_TABLE_H

#include <stdint.h>
#include <pthread.h>

#include "nf_defs.h"
#include "hash_functions/hash_functions.h"

#define NR_BUCKETS 1024 * 1024 /* Number of buckets, pow of 2 */

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

    hash_func_t hash_func;
} nf_table_t;

void nf_table_init(nf_table_t *nft, hash_func_t hash_func);
void nf_table_free(nf_table_t *nft);
int nf_table_add_or_update(nf_table_t *nft, nf_flow_t flow);
int nf_table_remove(nf_table_t *nft, nf_flow_spec_t flow_spec);
int nf_table_acquire_bucket(nf_table_t *nft, size_t index);
int nf_table_release_bucket(nf_table_t *nft, size_t index);

int bucket_entry_add(bucket_head_t *bkt, nf_flow_t flow);
int bucket_entry_update(bucket_entry_t *entry, nf_flow_export_t export_data);
int bucket_entry_remove(bucket_head_t *bkt, bucket_entry_t *entry);

#endif /* NF_TABLE_H */
