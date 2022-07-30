/*
 * Copyright (c) 2022 Dmitry Dolenko
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */

#include "netinet_helper.h"

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <fcntl.h>
#include <errno.h>

#include <stdio.h>

#define DEBUG_DUMMY 1

#if defined(DEBUG_DUMMY)
/* allowing to sniff all packet from interface */
#define SOCK_PROTO htons(ETH_P_ALL)
#else
/* read only incoming IP packets */
#define SOCK_PROTO htons(ETH_P_IP)
#endif

int init_raw_socket(int *raw_socket, const char *ifname, uint32_t *ifindex)
{
    struct sockaddr_ll addr;
    uint32_t if_index = if_nametoindex(ifname);

    if ((if_index == 0) && (errno != 0)) {
        return 0;
    }

    *raw_socket = socket(AF_PACKET, SOCK_RAW, SOCK_PROTO);
    if (*raw_socket == -1) {
        return 0;
    }

    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = if_index;
    addr.sll_protocol = SOCK_PROTO;
    if (bind(*raw_socket, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        close(*raw_socket);
        return 0;
    }

    if (fcntl(*raw_socket, F_SETFL, O_NONBLOCK) == -1) {
        close(*raw_socket);
        return 0;
    }

    *ifindex = if_index;

    return 1;
}

int parse_raw_packet(uint8_t *raw_packet, parsed_packet_t *parsed_packet)
{
    parsed_packet->eth = (struct ethhdr *)((uint8_t *)raw_packet);

#ifdef DEBUG_DUMMY
    if (parsed_packet->eth->h_proto != htons(ETH_P_IP)) {
        parsed_packet->upper_proto = UNSUPPORTED;
        return 0;
    }
#endif

    parsed_packet->ip =
        (struct iphdr *)((uint8_t *)parsed_packet->eth + sizeof(struct ethhdr));

    parsed_packet->upper_proto = parsed_packet->ip->protocol;
    switch (parsed_packet->upper_proto) {
    case ICMP:
    case TCP:
    case UDP:
        parsed_packet->upper_proto_ptr =
            (uint8_t *)((uint8_t *)parsed_packet->ip
                        + parsed_packet->ip->ihl * sizeof(uint32_t));
        break;
    default:
        parsed_packet->upper_proto = UNSUPPORTED;
        parsed_packet->upper_proto_ptr = NULL;
        break;
    }

    return (parsed_packet->upper_proto != UNSUPPORTED);
}
