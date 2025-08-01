/**
 * @file main.c
 * @brief Command-line interface for RSA-4096 with Montgomery REDC - Production Ready
 * 
 * @author TouanRichi
 * @date 2025-07-29 02:29:06 UTC
 * @version FINAL_COMPLETE_v7.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsa_4096.h"

int main(int argc, char **argv) {
    printf("[main:%d] Starting RSA-4096 application\n", __LINE__);
    if (argc < 2) {
        printf("Usage: %s [verify|test|benchmark|binary]\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "verify") == 0) {
        printf("[main:%d] Running verification mode (hex)\n", __LINE__);
        return run_verification();
    }
    if (strcmp(argv[1], "test") == 0) {
        printf("[main:%d] Running large RSA key testing\n", __LINE__);
        return test_large_rsa_keys();
    }
    if (strcmp(argv[1], "benchmark") == 0) {
        printf("[main:%d] Running performance benchmarks\n", __LINE__);
        return run_benchmarks();
    }
    if (strcmp(argv[1], "binary") == 0) {
        printf("[main:%d] Running binary operations verification\n", __LINE__);
        return run_binary_verification();
    }
    printf("Unknown command: %s\n", argv[1]);
    return 1;
}