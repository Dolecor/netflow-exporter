/*
 * Copyright (c) 2022 Dmitry Dolenko
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */

#include "nf_table.h"

#include <stdlib.h>
#include <string.h>

int bucket_entry_add(bucket_head_t *bkt, nf_flow_t flow)
{
    bucket_entry_t *new_entry =
        (bucket_entry_t *)malloc(sizeof(bucket_entry_t));
    new_entry->flow = flow;

    new_entry->next = bkt->head;
    bkt->head = new_entry;
}

int bucket_entry_update(bucket_entry_t *entry, nf_flow_export_t export_data)
{
    entry->flow.export_data.in_bytes += export_data.in_bytes;
    entry->flow.export_data.in_pkts += export_data.in_pkts;
    entry->flow.export_data.tcp_flags |= export_data.tcp_flags;
    entry->flow.export_data.last_switched = export_data.last_switched;
}

// TODO: replace linked list with doubly linked list for more effective remove operation
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

void nf_table_init(nf_table_t *nft, hash_func_t hash_func)
{
    nft->hash_func = hash_func;

    for (int i = 0; i < NR_BUCKETS; ++i) {
        nft->buckets[i].head = NULL;
        pthread_mutex_init(&nft->bkt_mutexes[i], NULL);
    }
}

void nf_table_free(nf_table_t *nft)
{
    for (int i = 0; i < NR_BUCKETS; ++i) {
        bucket_free(&(nft->buckets[i]));
        pthread_mutex_destroy(&nft->bkt_mutexes[i]);
    }
}
#include <stdio.h>
int nf_table_add(nf_table_t *nft, nf_flow_t flow)
{
    uint32_t hash =
        nft->hash_func(&flow.flow_spec, sizeof(nf_flow_spec_t)) % NR_BUCKETS;
    bucket_entry_t *it = nft->buckets[hash].head;

    pthread_mutex_lock(&nft->bkt_mutexes[hash]);

    while (it != NULL) {
        if (memcmp(&flow.flow_spec, &it->flow.flow_spec, sizeof(nf_flow_spec_t))
            == 0) {
            break;
        }
        it = it->next;
    }

    if (it == NULL) {
        bucket_entry_add(&nft->buckets[hash], flow);
        printf("Add new flow\n");
    }
    else {
        bucket_entry_update(it, flow.export_data);
        printf("Update flow\n");
    }

    pthread_mutex_unlock(&nft->bkt_mutexes[hash]);

    return (it == NULL);
}

int nf_table_remove(nf_table_t *nft, nf_flow_spec_t flow_spec)
{
    uint32_t hash =
        nft->hash_func(&flow_spec, sizeof(nf_flow_spec_t)) % NR_BUCKETS;
    bucket_entry_t *it = nft->buckets[hash].head;

    pthread_mutex_lock(&nft->bkt_mutexes[hash]);

    while (it != NULL) {
        if (memcmp(&flow_spec, &it->flow.flow_spec, sizeof(nf_flow_spec_t))
            == 0) {
            break;
        }
        it = it->next;
    }

    if (it != NULL) {
        bucket_entry_remove(&nft->buckets[hash], it);
    }

    pthread_mutex_unlock(&nft->bkt_mutexes[hash]);

    return (it != NULL);
}

int nf_table_acquire_bucket(nf_table_t *nft, size_t index)
{
    pthread_mutex_lock(&nft->bkt_mutexes[index]);
}

int nf_table_release_bucket(nf_table_t *nft, size_t index)
{
    pthread_mutex_unlock(&nft->bkt_mutexes[index]);
}
