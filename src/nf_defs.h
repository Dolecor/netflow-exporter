/*
 * Copyright (c) 2022 Dmitry Dolenko
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */

#ifndef NF_DEFS_H
#define NF_DEFS_H

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>

/* Netflow Export V9 field type definitions */
/* Namings are taken from NetFlow Version 9 Flow-Record Format, Table 6.
 * (https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html)
 */
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
    FLOWSET_TEMPLATE_ID = 0,
    FLOWSET_OPTIONS_ID = 1,
    FLOWSET_DATA_FIRST_ID = 256,
};

/* Scope types */
enum {
    SCOPE_SYSTEM = 1,
    SCOPE_INTERFACE = 2,
    SCOPE_LINECARD = 3,
    SCOPE_CACHE = 4,
    SCOPE_TEMPLATE = 5,
};

/* Flow definition */
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
    uint8_t ip_protocol;
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
    uint32_t last_switched;  /* ms */
    uint32_t first_switched; /* ms */
    uint16_t icmp_type;
    uint16_t flow_active_timeout;   /* secs */
    uint16_t flow_inactive_timeout; /* secs */
    uint16_t ipv4_ident;
    uint8_t in_src_mac[6];
    uint8_t in_dst_mac[6];
    uint8_t if_name[IF_NAMESIZE];
} nf_flow_export_t;

typedef struct nf_flow {
    nf_flow_spec_t flow_spec;
    nf_flow_export_t export_data;
} nf_flow_t;

/* RFC 3954: 5.1.  Header Format */
typedef struct export_packet_header {
    uint16_t version;
    uint16_t count;
    uint32_t sys_up_time; /* ms */
    uint32_t unix_secs;
    uint32_t sequence_number;
    uint32_t source_id;
} export_packet_header_t;

#define EXPORT_HEADER_SIZE sizeof(export_packet_header_t)
#define EXPORT_DATA_SIZE 1400
#define EXPORT_PACKET_SIZE (EXPORT_HEADER_SIZE + EXPORT_DATA_SIZE)
typedef struct export_packet {
    export_packet_header_t header;
    uint8_t *data[EXPORT_DATA_SIZE]; /* flowsets */
} export_packet_t;

/* RFC 3954: 5.2.  Template FlowSet Format */
typedef struct template_flowset {
    uint8_t flowset_id;
    uint8_t length;
    uint8_t template_id;
    uint8_t field_count;
} template_flowset_t;

/* RFC 3954: 5.3.  Data FlowSet Format */
typedef struct data_flowset {
    uint8_t flowset_id;
    uint8_t length;
} data_flowset_t;

/* RFC 3954: 6.1.  Options Template FlowSet Format */
typedef struct options_template_flowset {
    uint8_t flowset_id;
    uint8_t length;
    uint8_t template_id;
    uint8_t opt_scope_length;
    uint8_t option_length;
} options_template_flowset_t;

#endif /* NF_DEFS_H */
