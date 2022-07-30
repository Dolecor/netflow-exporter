/*
 * Copyright (c) 2022 Dmitry Dolenko
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */

#include "nf_export.h"

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
#include "nf_defs.h"
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
static uint32_t sys_boot_time_ms;

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
                           uint32_t sys_up_time);

static void *sniff_update(void *arg)
{
    struct sniff_update_arg args = *((struct sniff_update_arg *)arg);
    int exit_status = EXIT_SUCCESS;

    nf_flow_t flow;
    uint8_t raw_packet[PACKET_MAX_LEN];
    ssize_t num_bytes;
    parsed_packet_t parsed_packet;
    struct timeval tv;

    /* Constant parameters within this exporter. */
    flow.export_data.input_snmp = args.ifindex;
    strncpy(flow.export_data.if_name, args.ifname, IF_NAMESIZE);
    flow.export_data.flow_active_timeout = args.exp_cfg.flow_active_timeout;
    flow.export_data.flow_inactive_timeout = args.exp_cfg.flow_inactive_timeout;

    while (!stop_flag) {
        errno = 0;
        num_bytes = recvfrom(args.sock_sniff, raw_packet, PACKET_MAX_LEN, 0,
                             NULL, NULL);
        gettimeofday(&tv, NULL);
        if ((num_bytes == -1) && (errno != EAGAIN)) {
            perror("recvfrom");
            exit_status = EXIT_FAILURE;
            goto su_exit;
        } else if (errno == EAGAIN) {
            continue;
        }

        if (parse_raw_packet(raw_packet, &parsed_packet) == 1) {
            parsed_packet_to_flow(&parsed_packet, &flow,
                                  timeval_to_msec(tv) - sys_boot_time_ms);
            nf_table_add_or_update(&nft, flow);
        }
    }

su_exit:
    if (exit_status == EXIT_FAILURE) {
        raise(SIGTERM);
    }
    pthread_exit((void *)0);
}

static void *flows_checker(void *arg)
{
    struct flows_checker_arg args = *((struct flows_checker_arg *)arg);
    int exit_status = EXIT_SUCCESS;

    bucket_entry_t *it;
    bucket_entry_t *to_export;

    uint32_t firstseen;
    uint32_t lastseen;
    uint32_t active_timeout_ms = args.exp_cfg.flow_active_timeout * 1000;
    uint32_t inactive_timeout_ms = args.exp_cfg.flow_inactive_timeout * 1000;
    struct timeval tv;
    uint32_t sys_up_time;

    uint8_t export;

    while (!stop_flag) {
        for (int i = 0; i < NR_BUCKETS; ++i) {
            nf_table_acquire_bucket(&nft, i);
            it = nft.buckets[i].head;
            while (it != NULL) {
                firstseen = it->flow.export_data.first_switched;
                lastseen = it->flow.export_data.last_switched;
                gettimeofday(&tv, NULL);
                sys_up_time = timeval_to_msec(tv) - sys_boot_time_ms;

                /* RFC 3954: 3.2.  Flow Expiration */
                /* NOTE: implemented only *SHOULD*-conditions (2, 3) */

                /* 1. detect the end of a Flow *can* */
                /* 4. some other conditions *MAY* */

                export =
                    /* 2. export inactive flows */
                    (sys_up_time - lastseen > inactive_timeout_ms)
                    /* 3. export long-lasting flows */
                    || (lastseen - firstseen > active_timeout_ms);

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
    pthread_exit((void *)0);
}

void encode_nf_flow_export(struct data_record_all *dst, nf_flow_export_t *src);
int sendto_collector(int sock, struct sockaddr_in sockaddr,
                     export_packet_t *export_packet, size_t size);

#define TPL_FLOWSET_HDR(ptr) ((struct template_flowset_hdr *)ptr)
#define TPL_RECORD_ALL(ptr) ((struct template_record_all *)ptr)
#define DATA_FLOWSET_HDR(ptr) ((struct data_flowset_hdr *)ptr)
#define DATA_RECORD_ALL(ptr) ((struct data_record_all *)ptr)
static void *flows_exporter(void *arg)
{
    struct flows_exporter_arg args = *((struct flows_exporter_arg *)arg);
    int exit_status = EXIT_SUCCESS;

    struct sockaddr_in col_addr;
    ssize_t num_bytes;
    uint32_t seq_num = 0;
    uint16_t record_cnt = 0;
    size_t export_data_len = 0;
    size_t padding;
    uint8_t *data_ptr = NULL;
    export_packet_t export_packet = {
        .header.version = htons(9),
        .header.count = 0,
        .header.sys_up_time = 0,
        .header.unix_secs = 0,
        .header.sequence_number = 0,
        .header.source_id = htonl(args.ifindex),
    };
    struct template_flowset_hdr tpl_flowset_all_hdr = {
        .flowset_id = htons(TEMPLATE_FLOWSET_ID),
        .length = htons(sizeof(struct template_flowset_hdr)
                        + sizeof(struct template_record_all)),
    };
    struct template_record_all tpl_record_all = TPL_RECORD_ALL_INIT;
    struct data_flowset_hdr *data_flowset_all_hdr;
    nf_flow_export_t flow_to_export;

    memset(&col_addr, 0, sizeof(col_addr));
    col_addr.sin_family = AF_INET;
    col_addr.sin_addr.s_addr = args.col_cfg.ip;
    col_addr.sin_port = args.col_cfg.port;

    /* Fill template flowset */
    data_ptr = export_packet.data;

    *TPL_FLOWSET_HDR(data_ptr) = tpl_flowset_all_hdr;
    data_ptr += sizeof(struct template_flowset_hdr);
    export_data_len += sizeof(struct template_flowset_hdr);

    *TPL_RECORD_ALL(data_ptr) = tpl_record_all;
    data_ptr += sizeof(struct template_record_all);
    export_data_len += sizeof(struct template_record_all);

    export_packet.header.sequence_number += htonl(seq_num);
    export_packet.header.count = htons(1);

    if (sendto_collector(args.sock_col, col_addr, &export_packet,
                         sizeof(export_packet_header_t) + export_data_len)
        == 0) {
        perror("sendto_collector template flowset");
        exit_status = EXIT_FAILURE;
        goto fe_exit;
    }
    ++seq_num;

    while (!stop_flag) {
        /* Fill data flowset */
        export_data_len = 0;
        record_cnt = 0;

        data_ptr = export_packet.data;
        data_flowset_all_hdr = DATA_FLOWSET_HDR(data_ptr);
        data_flowset_all_hdr->flowset_id = htons(DATA_ALL_FLOWSET_ID);
        data_ptr += sizeof(struct data_flowset_hdr);
        export_data_len += sizeof(struct data_flowset_hdr);

        do {
            errno = 0;
            num_bytes =
                read(pipe_fc_fe[0], &flow_to_export, sizeof(nf_flow_export_t));
            if ((num_bytes == -1) && (errno != EAGAIN)) {
                perror("read");
                exit_status = EXIT_FAILURE;
                goto fe_exit;
            } else if ((num_bytes == 0) || (errno == EAGAIN)) {
                break;
            }

            encode_nf_flow_export(DATA_RECORD_ALL(data_ptr), &flow_to_export);
            data_ptr += sizeof(struct data_record_all);
            export_data_len += sizeof(struct data_record_all);
            record_cnt += 1;

        } while ((!stop_flag)
                 && ((export_data_len + sizeof(struct data_record_all)
                      < EXPORT_DATA_SIZE)));

        if (record_cnt != 0) {
            padding = export_data_len % DATA_FLOWSET_ALIGN;
            for (int i = 0; i < padding; ++i) {
                data_ptr[export_data_len + i] = 0;
            }
            export_data_len += padding;

            export_packet.header.count = htons(record_cnt);
            export_packet.header.sequence_number = htonl(seq_num);

            data_flowset_all_hdr->length = htons(export_data_len);

            if (sendto_collector(args.sock_col, col_addr, &export_packet,
                                 sizeof(export_packet_header_t)
                                     + export_data_len)
                == 0) {
                perror("sendto_collector data flowset");
                exit_status = EXIT_FAILURE;
                goto fe_exit;
            }
            ++seq_num;
        }
    }

fe_exit:
    if (exit_status == EXIT_FAILURE) {
        raise(SIGTERM);
    }
    pthread_exit((void *)0);
}

void parsed_packet_to_flow(parsed_packet_t *parsed_packet, nf_flow_t *flow,
                           uint32_t sys_up_time)
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
    flow->export_data.last_switched = sys_up_time;
    flow->export_data.first_switched = sys_up_time;
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

void encode_nf_flow_export(struct data_record_all *dst, nf_flow_export_t *src)
{
    dst->in_bytes = htonl(src->in_bytes);
    dst->in_pkts = htonl(src->in_pkts);
    dst->flows = htonl(src->flows);
    dst->protocol = src->protocol;
    dst->src_tos = src->src_tos;
    dst->tcp_flags = src->tcp_flags;
    dst->l4_src_port = src->l4_src_port;
    dst->ipv4_src_addr = src->ipv4_src_addr;
    dst->input_snmp = htons(src->input_snmp);
    dst->l4_dst_port = src->l4_dst_port;
    dst->ipv4_dst_addr = src->ipv4_dst_addr;
    dst->last_switched = htonl(src->last_switched);
    dst->first_switched = htonl(src->first_switched);
    dst->icmp_type = htons(src->icmp_type);
    dst->flow_active_timeout = htons(src->flow_active_timeout);
    dst->flow_inactive_timeout = htons(src->flow_inactive_timeout);
    dst->ipv4_ident = src->ipv4_ident;
    memcpy(dst->in_src_mac, src->in_src_mac, 6);
    memcpy(dst->in_dst_mac, src->in_dst_mac, 6);
    memcpy(dst->if_name, src->if_name, IF_NAMESIZE);
}

int sendto_collector(int sock, struct sockaddr_in sockaddr,
                     export_packet_t *export_packet, size_t size)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    export_packet->header.sys_up_time =
        htonl(timeval_to_msec(tv) - sys_boot_time_ms);
    export_packet->header.unix_secs = htonl(tv.tv_sec);

    return (sendto(sock, (void *)export_packet, size, 0,
                   (struct sockaddr *)&sockaddr, sizeof(sockaddr))
            != -1);
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

    struct timeval tv;
    gettimeofday(&tv, NULL);
    sys_boot_time_ms = timeval_to_msec(tv);

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
