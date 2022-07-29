/*
 * Copyright (c) 2022 Dmitry Dolenko
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */

#include "nf_export.h"

#define __USE_MISC 1 // for editor. TODO: delete this

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <pthread.h>
#include <signal.h>
#include <netinet/if_ether.h>
#include <fcntl.h>
#include <errno.h>

#include "netinet_helper.h"
#include "nf_table.h"
#include "utils.h"

volatile sig_atomic_t stop_flag;

void stop_handler(int sig)
{
    stop_flag = 1;
}

int set_signals()
{
    return (signal(SIGINT, stop_handler) != SIG_ERR)
           && (signal(SIGQUIT, stop_handler) != SIG_ERR)
           && (signal(SIGTERM, stop_handler) != SIG_ERR);
}

static nf_table_t nft;
static int pipe_fc_fe[2];

struct sniff_update_arg {
    int sock_sniff;
    char ifname[IF_NAMESIZE];
    uint32_t ifindex;
    exporter_config_t exp_cfg;
};

struct flows_checker_arg {
    exporter_config_t exp_cfg;
};

struct flows_exporter_arg {
    int sock_col;
    uint32_t ifindex;
    collector_config_t col_cfg;
};

void parsed_packet_to_flow(parsed_packet_t *parsed_packet, nf_flow_t *flow,
                           struct timeval ts);

static void *sniff_update(void *arg)
{
    struct sniff_update_arg args = *((struct sniff_update_arg *)arg);
    nf_flow_t flow;
    uint8_t raw_packet[PACKET_MAX_LEN];
    ssize_t num_bytes;
    parsed_packet_t parsed_packet;
    struct timeval ts;
    int exit_status = EXIT_SUCCESS;

    /* Constant parameters within this exporter. */
    flow.export_data.input_snmp = args.ifindex;
    strncpy(flow.export_data.if_name, args.ifname, IF_NAMESIZE);
    flow.export_data.flow_active_timeout = args.exp_cfg.flow_active_timeout;
    flow.export_data.flow_inactive_timeout = args.exp_cfg.flow_inactive_timeout;

    while (!stop_flag) {
        errno = 0;
        num_bytes = recvfrom(args.sock_sniff, raw_packet, PACKET_MAX_LEN, 0,
                             NULL, NULL);
        gettimeofday(&ts, NULL);
        if ((num_bytes == -1) && (errno != EAGAIN)) {
            perror("recvfrom");
            exit_status = EXIT_FAILURE;
            goto su_exit;
        } else if (errno == EAGAIN) {
            continue;
        }

        if (parse_raw_packet(raw_packet, &parsed_packet) == 1) {
            parsed_packet_to_flow(&parsed_packet, &flow, ts);
            nf_table_add(&nft, flow);
        }
    }

su_exit:
    if (exit_status == EXIT_FAILURE) {
        raise(SIGTERM);
    }
}

static void *flows_checker(void *arg)
{
    struct flows_checker_arg args = *((struct flows_checker_arg *)arg);
    bucket_entry_t *it;
    bucket_entry_t *to_export;

    uint32_t firstseen;
    uint32_t lastseen;
    uint32_t active_timeout_ms = args.exp_cfg.flow_active_timeout * 1000;
    uint32_t inactive_timeout_ms = args.exp_cfg.flow_inactive_timeout * 1000;
    struct timeval tv;
    uint32_t now_ms;

    uint8_t export;

    int exit_status = EXIT_SUCCESS;

    while (!stop_flag) {
        for (int i = 0; i < NR_BUCKETS; ++i) {
            nf_table_acquire_bucket(&nft, i);
            it = nft.buckets[i].head;
            while (it != NULL) {
                firstseen = it->flow.export_data.first_switched;
                lastseen = it->flow.export_data.last_switched;
                gettimeofday(&tv, NULL);
                now_ms = timeval_to_msec(tv);

                /* RFC 3954: 3.2.  Flow Expiration */

                /* 1. detect the end of a Flow */
                // TODO: check for FIN or RST in a TCP

                export =
                    /* 2. export inactive flows */
                    (now_ms - lastseen > inactive_timeout_ms)
                    /* 3. export long-lasting flows */
                    || (lastseen - firstseen > active_timeout_ms);

                /* 4. some other conditions */

                to_export = it;
                it = it->next;

                if (export) {
                    errno = 0;
                    if ((write(pipe_fc_fe[1], &to_export->flow.export_data,
                               sizeof(nf_flow_export_t))
                         == -1)
                        && (errno != EAGAIN)) {
                        perror("write");
                        exit_status = EXIT_FAILURE;
                        goto fc_exit;
                    }

                    bucket_entry_remove(&nft.buckets[i], to_export);
                }
            }
            nf_table_release_bucket(&nft, i);
        }
    }

fc_exit:
    if (exit_status == EXIT_FAILURE) {
        raise(SIGTERM);
    }
}

static void *flows_exporter(void *arg)
{
    struct flows_exporter_arg args = *((struct flows_exporter_arg *)arg);
    struct sockaddr_in col_addr;
    ssize_t num_bytes;
    nf_flow_export_t flow_export;
    export_packet_t export_packet;

    struct timeval tv;
    uint32_t sys_boot_time_ms;
    uint32_t now_ms;

    int exit_status = EXIT_SUCCESS;

    memset(&col_addr, 0, sizeof(col_addr));
    col_addr.sin_family = AF_INET;
    col_addr.sin_addr.s_addr = args.col_cfg.ip;
    col_addr.sin_port = args.col_cfg.port;

    export_packet.header.version = htons(9);
    export_packet.header.sequence_number = 0;
    export_packet.header.source_id = htonl(args.ifindex);

    gettimeofday(&tv, NULL);
    sys_boot_time_ms = timeval_to_msec(tv);

    /// 0. send Template Record to collector

    while (!stop_flag) {
        /// 1. read while export packet is full or no bytes was read
        do {
            errno = 0;
            num_bytes =
                read(pipe_fc_fe[0], &flow_export, sizeof(nf_flow_export_t));
            if ((num_bytes == -1) && (errno != EAGAIN)) {
                perror("read");
                exit_status = EXIT_FAILURE;
                goto fe_exit;
            }

            /// encode nf_flow_export_t to export_packet_t
        } while (/* export packet is full || */ (num_bytes == 0)
                 || (errno == EAGAIN));

        /// 2. send export packet to collector

        /// fill export_packet header (count, sysuptime, unix_secs,
        /// sequence_number)
    }

fe_exit:
    if (exit_status == EXIT_FAILURE) {
        raise(SIGTERM);
    }
}

void parsed_packet_to_flow(parsed_packet_t *parsed_packet, nf_flow_t *flow,
                           struct timeval ts)
{
    flow->flow_spec.src_ip = parsed_packet->ip->saddr;
    flow->flow_spec.dst_ip = parsed_packet->ip->daddr;
    flow->flow_spec.ip_tos = parsed_packet->ip->tos;
    flow->flow_spec.ip_protocol = parsed_packet->upper_proto;

    flow->export_data.in_bytes = ntohs(parsed_packet->ip->tot_len);
    flow->export_data.in_pkts = 1;
    flow->export_data.flows = 1;
    flow->export_data.protocol = parsed_packet->upper_proto;
    flow->export_data.src_tos = parsed_packet->ip->tos;
    flow->export_data.ipv4_src_addr = parsed_packet->ip->saddr;
    flow->export_data.ipv4_dst_addr = parsed_packet->ip->daddr;
    flow->export_data.last_switched = timeval_to_msec(ts);
    flow->export_data.first_switched = flow->export_data.last_switched;
    flow->export_data.ipv4_ident = parsed_packet->ip->frag_off;
    memcpy(flow->export_data.in_src_mac, parsed_packet->eth->h_source,
           ETH_ALEN);
    memcpy(flow->export_data.in_dst_mac, parsed_packet->eth->h_dest, ETH_ALEN);

    switch (flow->flow_spec.ip_protocol) {
    case ICMP:
        flow->flow_spec.src_port = 0;
        flow->flow_spec.icmp.type = parsed_packet->icmp->type;
        flow->flow_spec.icmp.code = parsed_packet->icmp->code;

        flow->export_data.icmp_type =
            parsed_packet->icmp->type * 256 + parsed_packet->icmp->code;
        flow->export_data.tcp_flags = 0;
        flow->export_data.l4_src_port = 0;
        flow->export_data.l4_dst_port = 0;
        break;
    case TCP:
        flow->flow_spec.src_port = parsed_packet->tcp->source;
        flow->flow_spec.dst_port = parsed_packet->tcp->dest;

        flow->export_data.icmp_type = 0;
        flow->export_data.tcp_flags = parsed_packet->tcp->th_flags;
        flow->export_data.l4_src_port = parsed_packet->tcp->source;
        flow->export_data.l4_dst_port = parsed_packet->tcp->dest;
        break;
    case UDP:
        flow->flow_spec.src_port = parsed_packet->udp->source;
        flow->flow_spec.dst_port = parsed_packet->udp->dest;

        flow->export_data.icmp_type = 0;
        flow->export_data.tcp_flags = 0;
        flow->export_data.l4_src_port = parsed_packet->udp->source;
        flow->export_data.l4_dst_port = parsed_packet->udp->dest;
        break;
    default:
        break;
    }
}

int init_collector_socket(int *sock)
{
    *sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (*sock == -1) {
        return 0;
    }

    return 1;
}

int export_start(const char *ifname, collector_config_t collector_cfg,
                 exporter_config_t exporter_cfg)
{
    int ret = EXIT_SUCCESS;
    pthread_t thr_su;
    pthread_t thr_fc;
    pthread_t thr_fe;
    struct sniff_update_arg su_arg;
    struct flows_checker_arg fc_arg;
    struct flows_exporter_arg fe_arg;

    hash_func_t hash_func;
    hash_func_init(&hash_func, MURMUR3_HASH);
    nf_table_init(&nft, hash_func);

    if (pipe(pipe_fc_fe) == -1) {
        perror("pipe");
        goto err_free;
    }
    if (fcntl(pipe_fc_fe[0], F_SETFL, O_NONBLOCK) == -1) {
        perror("fcntl");
        ret = EXIT_FAILURE;
        goto err_free;
    }

    if (!set_signals()) {
        ret = EXIT_FAILURE;
        goto err_free;
    }

    if (init_raw_socket(&su_arg.sock_sniff, ifname, &su_arg.ifindex) == 0) {
        perror("init_raw_socket");
        ret = EXIT_FAILURE;
        goto err_free;
    }
    strncpy(su_arg.ifname, ifname, IF_NAMESIZE);
    su_arg.exp_cfg = exporter_cfg;

    fc_arg.exp_cfg = exporter_cfg;

    if (init_collector_socket(&fe_arg.sock_col) == 0) {
        perror("init_collector_socket");
        ret = EXIT_FAILURE;
        goto err_free;
    }
    fe_arg.col_cfg = collector_cfg;

    errno = pthread_create(&thr_su, NULL, sniff_update, &su_arg);
    if (errno != 0) {
        perror("pthread_create(sniff_update)");
        ret = EXIT_FAILURE;
        goto err_free;
    }

    errno = pthread_create(&thr_fc, NULL, flows_checker, &fc_arg);
    if (errno != 0) {
        perror("pthread_create(flows_checker)");
        ret = EXIT_FAILURE;
        goto err_free;
    }

    errno = pthread_create(&thr_fe, NULL, flows_exporter, &fe_arg);
    if (errno != 0) {
        perror("pthread_create(flows_exporter)");
        ret = EXIT_FAILURE;
        goto err_free;
    }

    errno = pthread_join(thr_su, NULL);
    if (errno != 0) {
        perror("pthread_join(sniff_update)");
        ret = EXIT_FAILURE;
        goto err_free;
    }

    errno = pthread_join(thr_fc, NULL);
    if (errno != 0) {
        perror("pthread_join(flows_checker)");
        ret = EXIT_FAILURE;
        goto err_free;
    }

    errno = pthread_join(thr_fe, NULL);
    if (errno != 0) {
        perror("pthread_join(flows_exporter)");
        ret = EXIT_FAILURE;
        goto err_free;
    }

err_free:
    nf_table_free(&nft);
    close(pipe_fc_fe[0]);
    close(pipe_fc_fe[1]);
    close(su_arg.sock_sniff);
    close(fe_arg.sock_col);
exit:
    return ret;
}
