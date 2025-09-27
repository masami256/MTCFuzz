#define _GNU_SOURCE
#include "common.h"
#include "fuzz_params.h"
#include "ftpm_ta.h"
#include "ftpm_nv.h"

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

int verbose;

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s --target=nvwrite [--dev PATH] [--in FILE]\n"
        "\n"
        "Options:\n"
        "  --target=nvwrite     Select fuzz target (required for now)\n"
        "  --in FILE            Mutation text file (8-line hex format)\n"
        "  -h, --help           Show this help\n",
        prog);
}

static target_t parse_target(const char *s) {
    if (!s) {
        return TARGET_UNKNOWN;
    }
    if (strcmp(s, "nvwrite") == 0) {
        return TARGET_NVWRITE;
    }
    return TARGET_UNKNOWN;
}

static int parse_args(int argc, char **argv, options_t *out) {
    memset(out, 0, sizeof(*out));

    const struct option long_opts[] = {
        // name       has_arg            flag  val
        { "target",   required_argument, NULL,  1  },
        { "input",    required_argument, NULL,  2  },
        { "help",     no_argument,       NULL, 'h' },
        { "verbose",  no_argument,       NULL, 'v' },
        { 0,          0,                 0,     0  }
    };

    int opt, li;
    while ((opt = getopt_long(argc, argv, "h", long_opts, &li)) != -1) {
        switch (opt) {
        case 0:
            // Should not happen because we don't use flag pointers
            break;
        case 1: // --target
            out->target = parse_target(optarg);
            break;
        case 2: // --input
            out->infile = optarg;
            break;
        case 'v': // --verbose
            verbose = 1;
            break;
        case 'h':
            print_usage(argv[0]);
            return 1; // signal: help printed
        default:
            print_usage(argv[0]);
            return -1;
        }
    }

    if (out->target == TARGET_UNKNOWN) {
        IPRINTF("--target is required and must be 'nvwrite'\n\n");
        print_usage(argv[0]);
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    int rc = 0;
    options_t opt = {};

    if (parse_args(argc, argv, &opt)) {
        return -1;
    }

    switch (opt.target) {
    case TARGET_NVWRITE:
        DPRINTF("Target: nvwrite\n");
        opt.func = nv_write_start_fuzz_test;
        break;
    default:
        fprintf(stderr, "Unknown target (logic bug)\n");
        return 2;
    }

    DPRINTF("Test start\n");
    if (check_ftpm_ta()) {
         return -1;
    }
       
    DPRINTF("TA check ok\n");

    int fd = open_tpm_dev();
    if (fd < 0) {
        return -1;
    }
    opt.fd = fd;
    rc = opt.func(&opt);
    if (!rc) {
        IPRINTF("NV write/read test succeeded\n");
    } else {
        EPRINTF("NV write/read test failed\n");
    }

    close_tpm_dev(fd);
    return rc;
}
