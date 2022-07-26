/*
 * Copyright (c) 2022 Dmitry Dolenko
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */

#ifndef NF_EXPORT_H
#define NF_EXPORT_H

#include <arpa/inet.h>
#include <stdint.h>

typedef struct collector_info {
    in_addr_t ip;
    in_port_t port;
} collector_info_t;

int export_start(const char *if_name, collector_info_t collector);

#endif /* NF_EXPORT_H */
