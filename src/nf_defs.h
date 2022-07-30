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
#define IN_BYTES_LEN 4
    IN_BYTES = 1,
#define IN_PKTS_LEN 4
    IN_PKTS = 2,
#define FLOWS_LEN 4
    FLOWS = 3,
#define PROTOCOL_LEN 1
    PROTOCOL = 4,
#define SRC_TOS_LEN 1
    SRC_TOS = 5,
#define TCP_FLAGS_LEN 1
    TCP_FLAGS = 6,
#define L4_SRC_PORT_LEN 2
    L4_SRC_PORT = 7,
#define IPV4_SRC_ADDR_LEN 4
    IPV4_SRC_ADDR = 8,

#define INPUT_SNMP_LEN 2
    INPUT_SNMP = 10,
#define L4_DST_PORT_LEN 2
    L4_DST_PORT = 11,
#define IPV4_DST_ADDR_LEN 4
    IPV4_DST_ADDR = 12,

#define LAST_SWITCHED_LEN 4
    LAST_SWITCHED = 21,
#define FIRST_SWITCHED_LEN 4
    FIRST_SWITCHED = 22,

#define ICMP_TYPE_LEN 2
    ICMP_TYPE = 32,

#define FLOW_ACTIVE_TIMEOUT_LEN 2
    FLOW_ACTIVE_TIMEOUT = 36,
#define FLOW_INACTIVE_TIMEOUT_LEN 2
    FLOW_INACTIVE_TIMEOUT = 37,

#define IPV4_IDENT_LEN 2
    IPV4_IDENT = 54,

#define IN_SRC_MAC_LEN 6
    IN_SRC_MAC = 56,

#define IN_DST_MAC_LEN 6
    IN_DST_MAC = 80,

#define IF_NAME_LEN IF_NAMESIZE
    IF_NAME = 82,
};

/* Flowset IDs */
enum {
    TEMPLATE_FLOWSET_ID = 0,
    OPTIONS_FLOWSET_ID = 1,
    DATA_FLOWSET_FIRST_ID = 256,
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
    uint32_t ipv4_src_addr;
    uint16_t input_snmp;
    uint16_t l4_dst_port;
    uint32_t ipv4_dst_addr;
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

#define EXPORT_DATA_SIZE 1400
typedef struct export_packet {
    export_packet_header_t header;
    uint8_t data[EXPORT_DATA_SIZE]; /* flowsets */
} export_packet_t;

/* RFC 3954: 5.2.  Template FlowSet Format */
struct template_flowset_hdr {
    uint16_t flowset_id;
    uint16_t length;
    /* template_id, field_count */
    /* {field type, field length} pairs */
};

/* RFC 3954: 5.3.  Data FlowSet Format */
#define DATA_FLOWSET_ALIGN 4
struct data_flowset_hdr {
    uint16_t flowset_id;
    uint16_t length;
    /* Records + padding */
};

/* RFC 3954: 6.1.  Options Template FlowSet Format */
struct options_template_flowset_hdr {
    uint16_t flowset_id;
    uint16_t length;
    uint16_t template_id;
    uint16_t opt_scope_length;
    uint16_t option_length;
} __attribute__((packed));

/* Flowset records */

#define DATA_ALL_FLOWSET_ID DATA_FLOWSET_FIRST_ID
#define TYPES_ALL 20 /* All fields from nf_flow_export_t */
struct template_record_all {
    uint16_t template_id;
    uint16_t field_count;
    uint16_t fields[TYPES_ALL * 2]; /* {field type, field length} pairs */
};

#define TPL_RECORD_ADD_PAIR(type, i) \
    .fields[i] = htons(type), .fields[i + 1] = htons(type##_LEN)
#define TPL_RECORD_ALL_INIT                               \
    {                                                     \
        .template_id = htons(DATA_ALL_FLOWSET_ID),        \
        .field_count = htons(TYPES_ALL),                  \
        TPL_RECORD_ADD_PAIR(IN_BYTES, 0),                 \
        TPL_RECORD_ADD_PAIR(IN_PKTS, 2),                  \
        TPL_RECORD_ADD_PAIR(FLOWS, 4),                    \
        TPL_RECORD_ADD_PAIR(PROTOCOL, 6),                 \
        TPL_RECORD_ADD_PAIR(SRC_TOS, 8),                  \
        TPL_RECORD_ADD_PAIR(TCP_FLAGS, 10),               \
        TPL_RECORD_ADD_PAIR(L4_SRC_PORT, 12),             \
        TPL_RECORD_ADD_PAIR(IPV4_SRC_ADDR, 14),           \
        TPL_RECORD_ADD_PAIR(INPUT_SNMP, 16),              \
        TPL_RECORD_ADD_PAIR(L4_DST_PORT, 18),             \
        TPL_RECORD_ADD_PAIR(IPV4_DST_ADDR, 20),           \
        TPL_RECORD_ADD_PAIR(LAST_SWITCHED, 22),           \
        TPL_RECORD_ADD_PAIR(FIRST_SWITCHED, 24),          \
        TPL_RECORD_ADD_PAIR(ICMP_TYPE, 26),               \
        TPL_RECORD_ADD_PAIR(FLOW_ACTIVE_TIMEOUT, 28),     \
        TPL_RECORD_ADD_PAIR(FLOW_INACTIVE_TIMEOUT, 30),   \
        TPL_RECORD_ADD_PAIR(IPV4_IDENT, 32),              \
        TPL_RECORD_ADD_PAIR(IN_SRC_MAC, 34),              \
        TPL_RECORD_ADD_PAIR(IN_DST_MAC, 36),              \
        TPL_RECORD_ADD_PAIR(IF_NAME, 38),                 \
    }

struct data_record_all {
    uint32_t in_bytes;
    uint32_t in_pkts;
    uint32_t flows;
    uint8_t protocol;
    uint8_t src_tos;
    uint8_t tcp_flags;
    uint16_t l4_src_port;
    uint32_t ipv4_src_addr;
    uint16_t input_snmp;
    uint16_t l4_dst_port;
    uint32_t ipv4_dst_addr;
    uint32_t last_switched;
    uint32_t first_switched;
    uint16_t icmp_type;
    uint16_t flow_active_timeout;
    uint16_t flow_inactive_timeout;
    uint16_t ipv4_ident;
    uint8_t in_src_mac[6];
    uint8_t in_dst_mac[6];
    uint8_t if_name[IF_NAMESIZE];
} __attribute__((packed));

#endif /* NF_DEFS_H */
