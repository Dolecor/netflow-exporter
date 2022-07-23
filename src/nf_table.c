/*
 * Copyright (c) 2022 Dmitry Dolenko
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */

#include "nf_table.h"

#include <stdlib.h>
#include <string.h>

#include <stdio.h>

int bucket_entry_add(bucket_head_t *bkt, nf_flow_spec_t flow_spec)
{
    bucket_entry_t *new_entry =
        (bucket_entry_t *)malloc(sizeof(bucket_entry_t));
    new_entry->flow.flow_spec = flow_spec;

    new_entry->next = bkt->head;
    bkt->head = new_entry;
}

int bucket_entry_remove(bucket_head_t *bkt, bucket_entry_t *entry)
{
    bucket_entry_t *it;
    bucket_entry_t *prev;

    if (bkt->head == entry) {
        bkt->head = bkt->head->next;
        free(entry);
        return 1;
    }
    prev = bkt->head;
    it = bkt->head->next;

    while (it != NULL) {
        if (it == entry) {
            prev->next = entry->next;
            free(entry);
            return 1;
        }
        prev = it;
        it = it->next;
    }

    return 0;
}

void bucket_free(bucket_head_t *bkt)
{
    bucket_entry_t *it = bkt->head;

    while (it != NULL) {
        bkt->head = bkt->head->next;
        free(it);
        it = bkt->head;
    }
}

void nf_table_init(nf_table_t **nft, hash_func_t hash_func)
{

    *nft = (nf_table_t *)malloc(sizeof(nf_table_t));
    (*nft)->size = 0;
    (*nft)->hash_func = hash_func;

    for (int i = 0; i < NR_BUCKETS; ++i) {
        (*nft)->buckets[i].head = NULL;
        pthread_mutex_init(&((*nft)->bkt_mutexes[i]), NULL);
    }
}

void nf_table_free(nf_table_t **nft)
{
    for (int i = 0; i < NR_BUCKETS; ++i) {
        bucket_free(&((*nft)->buckets[i]));
        pthread_mutex_destroy(&((*nft)->bkt_mutexes[i]));
    }

    free(*nft);
    *nft = NULL;
}

int nf_table_add(nf_table_t *nft, nf_flow_spec_t flow_spec)
{
    uint32_t hash =
        nft->hash_func(&flow_spec, sizeof(nf_flow_spec_t)) % NR_BUCKETS;
    bucket_entry_t *it = nft->buckets[hash].head;

    while (it != NULL) {
        if (memcmp(&flow_spec, &it->flow.flow_spec, sizeof(nf_flow_spec_t))
            == 0) {
            break;
        }
        it = it->next;
    }

    if (it == NULL) {
        bucket_entry_add(&nft->buckets[hash], flow_spec);
        ++nft->size;
    }

    return (it == NULL);
}

int nf_table_remove(nf_table_t *nft, nf_flow_spec_t flow_spec)
{
    uint32_t hash =
        nft->hash_func(&flow_spec, sizeof(nf_flow_spec_t)) % NR_BUCKETS;
    bucket_entry_t *it = nft->buckets[hash].head;

    while (it != NULL) {
        if (memcmp(&flow_spec, &it->flow.flow_spec, sizeof(nf_flow_spec_t))
            == 0) {
            break;
        }
        it = it->next;
    }

    if (it != NULL) {
        bucket_entry_remove(&nft->buckets[hash], it);
        --nft->size;
    }

    return (it != NULL);
}
