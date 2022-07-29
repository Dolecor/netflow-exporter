/*
 * Copyright (c) 2022 Dmitry Dolenko
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */

#ifndef NF_EXPORT_H
#define NF_EXPORT_H

#include <arpa/inet.h>
#include <stdint.h>

typedef struct collector_config {
    in_addr_t ip;
    in_port_t port;
} collector_config_t;

typedef struct exporter_config {
    uint16_t flow_active_timeout;
    uint16_t flow_inactive_timeout;
} exporter_config_t;

int export_start(const char *if_name, collector_config_t collector_cfg,
                 exporter_config_t exporter_cfg);

#endif /* NF_EXPORT_H */
