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
#include <net/if.h>
#include <getopt.h>
#include <limits.h>

#include "nf_table.h"
#include <assert.h>
#include "hash_functions/hash_functions.h"

#define PROGRAM_NAME "nfexp"

typedef struct options {
    char if_name[IF_NAMESIZE];
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
    fprintf(stderr, "  -i                      Interface name (e.g. eth0)\n");
    fprintf(
        stderr,
        "  -c                      IP address and UDP port number of the host\n"
        "                          with NetFlow collector in format IP:port\n");

    exit(EXIT_FAILURE);
}

static void parse_options(int argc, char *argv[], options_t *options)
{
    int opt;

    enum {
        A = CHAR_MAX + 1,
    };

    static const struct option long_opts[] = {{"help", no_argument, NULL, 'h'},
                                              {NULL, 0, NULL, 0}};

    while ((opt = getopt_long(argc, argv, "h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'h':
            print_help_and_exit(NULL);
        default:
            print_help_and_exit(NULL);
        }
    }

    if (optind < argc) {
        strncpy(options->if_name, argv[optind], IF_NAMESIZE);
    } else {
        print_help_and_exit("Interface name must be specified.");
    }
}

int main(int argc, char *argv[])
{
    // int ret;
    // options_t options;

    // parse_options(argc, argv, &options);
    // ret = EXIT_SUCCESS;

    // exit(ret);

    nf_table_t *nft;
    hash_func_t hash_func;
    nf_flow_spec_t flow_spec;
    int ret;

    hash_func_init(&hash_func, MURMUR3_HASH);
    nf_table_init(&nft, hash_func);

    for (int i = 0; i < 1024; ++i) {
        flow_spec.dst_ip = i;
        nf_table_add(nft, flow_spec);
    }

    flow_spec.dst_ip = 10;
    ret = nf_table_add(nft, flow_spec);
    assert(ret == 0);
    ret = nf_table_remove(nft, flow_spec);
    assert(ret == 1);
    ret = nf_table_remove(nft, flow_spec);
    assert(ret == 0);

    nf_table_free(&nft);

    return 0;
}
