/*
 * Copyright (c) 2022 Dmitry Dolenko
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */

#ifndef NF_FLOW_H
#define NF_FLOW_H

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>

/* Netflow Export V9 field type definitions */
enum {
    IN_BYTES = 1,
    IN_PKTS = 2,
    FLOWS = 3,
    PROTOCOL = 4,
    SRC_TOS = 5,
    TCP_FLAGS = 6,
    L4_SRC_PORT = 7,
    IPV4_SRC_ADDR = 8,

    INPUT_SNMP = 10,
    L4_DST_PORT = 11,
    IPV4_DST_ADDR = 12,

    LAST_SWITCHED = 21,
    FIRST_SWITCHED = 22,

    ICMP_TYPE = 32,

    FLOW_ACTIVE_TIMEOUT = 36,
    FLOW_INACTIVE_TIMEOUT = 37,

    IPV4_IDENT = 54,

    IN_SRC_MAC = 56,

    IN_DST_MAC = 80,

    IF_NAME = 82,
};

/* Flowset IDs */
enum {
    FLOWSET_TEMPLATE = 0,
    FLOWSET_OPTIONS = 1,
    FLOWSET_DATA_FIRST = 256,
};

/* Scope types */
enum {
    SCOPE_SYSTEM = 1,
    SCOPE_INTERFACE = 2,
    SCOPE_LINECARD = 3,
    SCOPE_CACHE = 4,
    SCOPE_TEMPLATE = 5,
};

typedef struct nf_flow_spec {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    union {
        uint16_t dst_port;
        struct {
            uint8_t type;
            uint8_t code;
        } icmp;
    };
    uint8_t l4_protocol;
    uint8_t ip_tos;
} nf_flow_spec_t;

typedef struct nf_flow_export {
    uint32_t in_bytes;
    uint32_t in_pkts;
    uint32_t flows;
    uint8_t protocol;
    uint8_t src_tos;
    uint8_t tcp_flags;
    uint16_t l4_src_port;
    uint16_t ipv4_src_addr;
    uint16_t input_snmp;
    uint16_t l4_dst_port;
    uint16_t ipv4_dst_addr;
    uint32_t last_switched;
    uint32_t first_switched;
    uint16_t icmp_type;
    uint16_t flow_active_timeout;
    uint16_t flow_inactive_timeout;
    uint16_t ipv4_ident;
    uint8_t in_src_mac[6];
    uint8_t in_dst_mac[6];
    uint8_t if_name[IF_NAMESIZE];
} nf_flow_export_t;

typedef struct nf_flow {
    nf_flow_spec_t flow_spec;
    nf_flow_export_t export_data;
} nf_flow_t;

#endif /* NF_FLOW_H */
