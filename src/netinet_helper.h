/*
 * Copyright (c) 2022 Dmitry Dolenko
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */

#ifndef NETINET_HELPER_H
#define NETINET_HELPER_H

#include <stdint.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#define _DEFAULT_SOURCE 1
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define PACKET_MAX_LEN IP_MAXPACKET

int init_raw_socket(int *raw_socket, const char *ifname, uint32_t *ifindex);

enum upper_protocol {
    UNSUPPORTED = -1,
    ICMP = IPPROTO_ICMP, /* 1 */
    TCP = IPPROTO_TCP,   /* 6 */
    UDP = IPPROTO_UDP,   /* 17 */
};

typedef struct parsed_packet {
    struct ethhdr *eth;
    struct iphdr *ip;
    enum upper_protocol upper_proto;
    union {
        uint8_t *upper_proto_ptr; /* NULL if protocol_type == UNSUPPORTED */
        struct icmphdr *icmp;
        struct tcphdr *tcp;
        struct udphdr *udp;
    };
} parsed_packet_t;

int parse_raw_packet(uint8_t *raw_packet, parsed_packet_t *parsed_packet);

#endif /* NETINET_HELPER_H */
