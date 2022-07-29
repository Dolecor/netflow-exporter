/*
 * Copyright (c) 2022 Dmitry Dolenko
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <getopt.h>
#include <limits.h>
#include <errno.h>

#include "nf_export.h"

#define PROGRAM_NAME "nfexp"

typedef struct options {
    char if_name[IF_NAMESIZE];
    collector_config_t col_cfg;
} options_t;

static void print_help_and_exit(char *msg)
{
    if (msg != NULL) {
        fprintf(stderr, "%s\n\n", msg);
    }
    fprintf(stderr, "Usage: %s [options]\n", PROGRAM_NAME);
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -h, --help              Print this help and exit\n");
    fprintf(stderr, "  -i <ifname>             Interface name (e.g. eth0)\n");
    fprintf(stderr, "  -c <IP:port>            IP address and UDP port number of the host\n"
                    "                          with NetFlow collector in format IP:port\n");

    exit(EXIT_FAILURE);
}

static int parse_collector(const char *buf, uint32_t *ip, uint16_t *port);

static void parse_options(int argc, char *argv[], options_t *options)
{
    int opt;
    int ifname = 0;
    int colstr = 0;

    static const struct option long_opts[] = {
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    while ((opt = getopt_long(argc, argv, "i:c:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i':
            strncpy(options->if_name, optarg, IF_NAMESIZE);
            ifname = 1;
            break;
        case 'c':
            if (parse_collector(optarg, &options->col_cfg.ip,
                                &options->col_cfg.port)
                < 0) {
                print_help_and_exit("Invalid collector string format.");
            }
            colstr = 1;
            break;
        case 'h':
            print_help_and_exit(NULL);
        default:
            print_help_and_exit(NULL);
        }
    }

    if (ifname == 0) {
        print_help_and_exit("Interface name must be specified with -i option.");
    }
    if (colstr == 0) {
        print_help_and_exit("IP address and UDP port number of collector\n"
                            "must be specified with -c option.");
    }
}

/* Collector string. x - ip, y - port */
#define COLLECTOR_STR_LEN sizeof("xxx.xxx.xxx.xxx:yyyyy")
#define PORT_STR_LEN 6
#define MAX_PORT 65535

int parse_collector(const char *buf, in_addr_t *ip, in_port_t *port)
{
    const char delim[] = ":";
    char *token;
    char col_str[COLLECTOR_STR_LEN];
    char ip_str[INET_ADDRSTRLEN];
    char port_str[PORT_STR_LEN];

    strncpy(col_str, buf, COLLECTOR_STR_LEN);

    /* ip */
    token = strtok(col_str, delim);
    if (token == NULL) {
        return -1;
    }

    strcpy(ip_str, token);
    *ip = inet_addr(ip_str);
    if (*ip == (in_addr_t)(-1)) {
        fprintf(stderr, "%s is not valid ip address.\n", ip_str);
        return -1;
    }

    /* port */
    token = strtok(NULL, delim);
    if (token == NULL) {
        return -2;
    }

    if (strlen(token) > PORT_STR_LEN - 1) {
        fprintf(stderr, "%s is not valid port number.\n", token);
        return -2;
    } else {
        strcpy(port_str, token);
        char *endptr;
        uint32_t tmp = (uint32_t)strtoll(port_str, &endptr, 0);

        if ((errno != 0) || (endptr == port_str)
            || (tmp < 1) || (tmp > MAX_PORT)) {
            fprintf(stderr, "%s is not valid port number.\n", port_str);
            return -2;
        }

        *port = htons(tmp);
    }

    return 1;
}
#include "nf_defs.h"
#include "nf_table.h"
#include "hash_functions/hash_functions.h"
#include <assert.h>
int main(int argc, char *argv[])
{
    int ret;
    options_t options;
    exporter_config_t exp_cfg = {.flow_active_timeout = 30,
                                 .flow_inactive_timeout = 15};

    parse_options(argc, argv, &options);
    ret = export_start(options.if_name, options.col_cfg, exp_cfg);

    exit(ret);
 }
