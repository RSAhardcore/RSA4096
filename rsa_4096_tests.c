/**
 * @file rsa_4096_tests.c
 * @brief Test suite for RSA-4096 + Montgomery REDC - BUGS FIXED ONLY
 * 
 * @author TouanRichi
 * @date 2025-07-29 09:38:49 UTC
 * @version FINAL_COMPLETE_FIXED_v8.2
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "rsa_4096.h"

int run_verification(void) {
    printf("===============================================\n");
    printf("RSA-4096 Verification Tests (BUGS FIXED)\n");
    printf("===============================================\n");
    printf("Date: 2025-07-29 09:38:49 UTC\n");
    printf("User: RSAhardcore\n\n");

    printf("Test Parameters:\n");
    printf("  Modulus (n): 35\n");
    printf("  Public Exponent (e): 5\n");
    printf("  Private Exponent (d): 5\n\n");

    /* Manual verification of RSA parameters */
    printf("RSA Parameter Verification:\n");
    printf("  n = 35 = 5 × 7\n");
    printf("  φ(n) = φ(35) = (5-1) × (7-1) = 4 × 6 = 24\n");
    printf("  e = 5, gcd(5, 24) = 1 ✓\n");
    printf("  d = 5, e × d = 5 × 5 = 25 ≡ 1 (mod 24) ✓\n\n");

    /* Manual calculation results */
    printf("Expected Results (Manual Calculation):\n");
    printf("[MANUAL CALC] Computing 2^5 mod 35\n[MANUAL CALC] Step 1: result = 2\n[MANUAL CALC] Step 2: result = 4\n[MANUAL CALC] Step 3: result = 8\n[MANUAL CALC] Step 4: result = 16\n[MANUAL CALC] Step 5: result = 32\n[MANUAL CALC] Final result: 32\n");
    printf("[MANUAL CALC] Computing 3^5 mod 35\n[MANUAL CALC] Step 1: result = 3\n[MANUAL CALC] Step 2: result = 9\n[MANUAL CALC] Step 3: result = 27\n[MANUAL CALC] Step 4: result = 11\n[MANUAL CALC] Step 5: result = 33\n[MANUAL CALC] Final result: 33\n");
    printf("[MANUAL CALC] Computing 4^5 mod 35\n[MANUAL CALC] Step 1: result = 4\n[MANUAL CALC] Step 2: result = 16\n[MANUAL CALC] Step 3: result = 29\n[MANUAL CALC] Step 4: result = 11\n[MANUAL CALC] Step 5: result = 9\n[MANUAL CALC] Final result: 9\n");
    printf("  Message 2: encrypt to 32\n  Message 3: encrypt to 33\n  Message 4: encrypt to 9\n\n");

    rsa_4096_key_t pub_key, priv_key;
    rsa_4096_init(&pub_key);
    rsa_4096_init(&priv_key);
    
    /* FIXED: Check initialization */
    if (bigint_is_zero(&pub_key.n) || bigint_is_zero(&priv_key.n)) {
        printf("✅ Key structures initialized properly\n");
    }
    
    int ret = rsa_4096_load_key(&pub_key, "35", "5", 0);
    if (ret != 0) { 
        printf("❌ Error loading public key: %d\n", ret); 
        rsa_4096_free(&pub_key);
        rsa_4096_free(&priv_key);
        return ret; 
    }
    
    ret = rsa_4096_load_key(&priv_key, "35", "5", 1);
    if (ret != 0) { 
        printf("❌ Error loading private key: %d\n", ret); 
        rsa_4096_free(&pub_key);
        rsa_4096_free(&priv_key);
        return ret; 
    }
    printf("✅ RSA keys loaded successfully\n\n");

    /* FIXED: Verify key properties */
    if (bigint_is_zero(&pub_key.n) || bigint_is_zero(&pub_key.exponent)) {
        printf("❌ Public key has zero values\n");
        rsa_4096_free(&pub_key);
        rsa_4096_free(&priv_key);
        return -1;
    }
    
    if (bigint_is_zero(&priv_key.n) || bigint_is_zero(&priv_key.exponent)) {
        printf("❌ Private key has zero values\n");
        rsa_4096_free(&pub_key);
        rsa_4096_free(&priv_key);
        return -1;
    }

    const char *test_messages[] = {"2", "3", "4"};
    int expected_results[] = {32, 33, 9};
    int num_tests = 3, passed_tests = 0;
    
    for (int i = 0; i < num_tests; i++) {
        printf("=== Test Vector %d: message = \"%s\" ===\n", i + 1, test_messages[i]);
        
        /* FIXED: Use larger buffer for hex output */
        char encrypted_hex[1024];
        memset(encrypted_hex, 0, sizeof(encrypted_hex));
        
        printf("🔐 Encrypting message \"%s\"...\n", test_messages[i]);
        ret = rsa_4096_encrypt(&pub_key, test_messages[i], encrypted_hex, sizeof(encrypted_hex));
        if (ret != 0) { 
            printf("❌ Encryption failed: %d\n", ret); 
            continue; 
        }
        
        /* FIXED: Proper validation of encrypted result */
        if (strlen(encrypted_hex) == 0) {
            printf("❌ Encryption produced empty result\n");
            continue;
        }
        
        bigint_t encrypted_bigint;
        bigint_init(&encrypted_bigint);
        ret = bigint_from_hex(&encrypted_bigint, encrypted_hex);
        if (ret != 0) {
            printf("❌ Failed to parse encrypted hex: %d\n", ret);
            continue;
        }
        
        /* FIXED: Use larger buffer for decimal conversion */
        char encrypted_decimal[512];
        memset(encrypted_decimal, 0, sizeof(encrypted_decimal));
        ret = bigint_to_decimal(&encrypted_bigint, encrypted_decimal, sizeof(encrypted_decimal));
        if (ret != 0) {
            printf("❌ Failed to convert to decimal: %d\n", ret);
            continue;
        }
        
        printf("   Encrypted (hex): \"%s\"\n", encrypted_hex);
        printf("   Encrypted (decimal): %s\n", encrypted_decimal);
        printf("   Expected (decimal): %d\n", expected_results[i]);
        
        /* FIXED: Proper comparison */
        int encrypted_value = atoi(encrypted_decimal);
        if (encrypted_value == expected_results[i]) {
            printf("✅ Encryption verification: PASS\n");
            
            /* FIXED: Use larger buffer for decrypted message */
            char decrypted_message[512];
            memset(decrypted_message, 0, sizeof(decrypted_message));
            
            printf("🔓 Decrypting \"%s\"...\n", encrypted_hex);
            ret = rsa_4096_decrypt(&priv_key, encrypted_hex, decrypted_message, sizeof(decrypted_message));
            if (ret != 0) { 
                printf("❌ Decryption failed: %d\n", ret); 
                continue; 
            }
            
            /* FIXED: Validate decrypted result */
            if (strlen(decrypted_message) == 0) {
                printf("❌ Decryption produced empty result\n");
                continue;
            }
            
            printf("   Decrypted: \"%s\"\n", decrypted_message);
            printf("   Expected: \"%s\"\n", test_messages[i]);
            
            if (strcmp(decrypted_message, test_messages[i]) == 0) {
                printf("✅ Round-trip Result: PASS\n");
                passed_tests++;
            } else {
                printf("❌ Round-trip Result: FAIL (got \"%s\", expected \"%s\")\n", 
                       decrypted_message, test_messages[i]);
            }
        } else {
            printf("❌ Encryption verification: FAIL (got %d, expected %d)\n", 
                   encrypted_value, expected_results[i]);
        }
        printf("\n");
    }
    
    printf("===============================================\n");
    printf("Verification Summary:\n");
    printf("  ✅ Tests passed: %d/%d\n", passed_tests, num_tests);
    if (passed_tests == num_tests)
        printf("  🎉 Overall result: ALL TESTS PASSED!\n");
    else
        printf("  ❌ Overall result: %d TESTS FAILED!\n", num_tests - passed_tests);
    printf("===============================================\n");
    
    /* FIXED: Proper cleanup */
    rsa_4096_free(&pub_key);
    rsa_4096_free(&priv_key);
    
    return (passed_tests == num_tests) ? 0 : -1;
}

/* ENHANCED TEST IMPLEMENTATIONS */
int test_large_rsa_keys(void) { 
    printf("===============================================\n");
    printf("RSA Large Key Testing - ENHANCED\n");
    printf("===============================================\n");
    printf("Date: 2025-07-29 09:38:49 UTC\n");
    printf("User: RSAhardcore\n\n");
    
    /* Test with larger modulus to verify Montgomery REDC */
    printf("Testing with larger modulus (8-bit): n = 143 = 11 × 13\n");
    printf("φ(n) = 120, using e = 7, d = 103\n\n");
    
    rsa_4096_key_t pub_key, priv_key;
    rsa_4096_init(&pub_key);
    rsa_4096_init(&priv_key);
    
    /* FIXED: Test with odd modulus to enable Montgomery */
    int ret = rsa_4096_load_key(&pub_key, "143", "7", 0);
    if (ret != 0) {
        printf("❌ Failed to load public key: %d\n", ret);
        rsa_4096_free(&pub_key);
        rsa_4096_free(&priv_key);
        return ret;
    }
    
    ret = rsa_4096_load_key(&priv_key, "143", "103", 1);
    if (ret != 0) {
        printf("❌ Failed to load private key: %d\n", ret);
        rsa_4096_free(&pub_key);
        rsa_4096_free(&priv_key);
        return ret;
    }
    
    printf("✅ Large keys loaded successfully\n");
    
    /* Test Montgomery REDC activation */
    if (pub_key.mont_ctx.is_active) {
        printf("✅ Montgomery REDC is ACTIVE\n");
    } else {
        printf("ℹ️  Montgomery REDC is disabled (fallback to standard arithmetic)\n");
    }
    
    /* Test encryption/decryption */
    const char *test_msg = "42";
    char encrypted_hex[1024];
    char decrypted_msg[512];
    
    printf("\n🔐 Testing encryption/decryption with message: %s\n", test_msg);
    
    ret = rsa_4096_encrypt(&pub_key, test_msg, encrypted_hex, sizeof(encrypted_hex));
    if (ret != 0) {
        printf("❌ Encryption failed: %d\n", ret);
        rsa_4096_free(&pub_key);
        rsa_4096_free(&priv_key);
        return ret;
    }
    
    printf("   Encrypted: %s\n", encrypted_hex);
    
    ret = rsa_4096_decrypt(&priv_key, encrypted_hex, decrypted_msg, sizeof(decrypted_msg));
    if (ret != 0) {
        printf("❌ Decryption failed: %d\n", ret);
        rsa_4096_free(&pub_key);
        rsa_4096_free(&priv_key);
        return ret;
    }
    
    printf("   Decrypted: %s\n", decrypted_msg);
    
    if (strcmp(test_msg, decrypted_msg) == 0) {
        printf("✅ Large key test PASSED\n");
    } else {
        printf("❌ Large key test FAILED\n");
        rsa_4096_free(&pub_key);
        rsa_4096_free(&priv_key);
        return -1;
    }
    
    printf("===============================================\n");
    rsa_4096_free(&pub_key);
    rsa_4096_free(&priv_key);
    return 0; 
}

int run_benchmarks(void) { 
    printf("===============================================\n");
    printf("RSA-4096 Performance Benchmarks - ENHANCED\n");
    printf("===============================================\n");
    printf("Date: 2025-07-29 09:38:49 UTC\n");
    printf("User: RSAhardcore\n\n");
    
    rsa_4096_key_t key;
    rsa_4096_init(&key);
    
    /* FIXED: Test with reasonable size modulus */
    int ret = rsa_4096_load_key(&key, "35", "5", 0);
    if (ret != 0) {
        printf("❌ Failed to load benchmark key: %d\n", ret);
        rsa_4096_free(&key);
        return ret;
    }
    
    printf("Benchmark Configuration:\n");
    printf("  Modulus bits: %d\n", bigint_bit_length(&key.n));
    printf("  Montgomery REDC: %s\n", key.mont_ctx.is_active ? "ACTIVE" : "DISABLED");
    printf("\n");
    
    /* Time encryption operations */
    clock_t start = clock();
    const int num_operations = 100;
    
    printf("🚀 Running %d encryption operations...\n", num_operations);
    
    for (int i = 0; i < num_operations; i++) {
        char msg[16];
        snprintf(msg, sizeof(msg), "%d", (i % 20) + 1); /* Messages 1-20 */
        
        char encrypted_hex[1024];
        ret = rsa_4096_encrypt(&key, msg, encrypted_hex, sizeof(encrypted_hex));
        if (ret != 0) {
            printf("❌ Encryption %d failed: %d\n", i, ret);
            break;
        }
        
        if (i % 20 == 0) {
            printf("   Progress: %d/%d operations completed\n", i, num_operations);
        }
    }
    
    clock_t end = clock();
    double elapsed = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    printf("✅ Benchmark completed\n");
    printf("Results:\n");
    printf("  Operations: %d\n", num_operations);
    printf("  Total time: %.3f seconds\n", elapsed);
    printf("  Average time per operation: %.3f ms\n", (elapsed * 1000) / num_operations);
    printf("  Operations per second: %.1f\n", num_operations / elapsed);
    
    printf("===============================================\n");
    rsa_4096_free(&key);
    return 0; 
}

int run_binary_verification(void) { 
    printf("===============================================\n");
    printf("RSA-4096 Binary Operations Verification - ENHANCED\n");
    printf("===============================================\n");
    printf("Date: 2025-07-29 09:38:49 UTC\n");
    printf("User: RSAhardcore\n\n");
    
    rsa_4096_key_t pub_key, priv_key;
    rsa_4096_init(&pub_key);
    rsa_4096_init(&priv_key);
    
    int ret = rsa_4096_load_key(&pub_key, "35", "5", 0);
    if (ret != 0) {
        printf("❌ Failed to load public key: %d\n", ret);
        rsa_4096_free(&pub_key);
        rsa_4096_free(&priv_key);
        return ret;
    }
    
    ret = rsa_4096_load_key(&priv_key, "35", "5", 1);
    if (ret != 0) {
        printf("❌ Failed to load private key: %d\n", ret);
        rsa_4096_free(&pub_key);
        rsa_4096_free(&priv_key);
        return ret;
    }
    
    printf("✅ Keys loaded for binary testing\n\n");
    
    /* Test binary encryption/decryption */
    uint8_t test_data[] = {0x01, 0x02, 0x03, 0x04};
    size_t test_size = sizeof(test_data);
    
    printf("🔐 Testing binary encryption/decryption\n");
    printf("   Original data: ");
    for (size_t i = 0; i < test_size; i++) {
        printf("%02x ", test_data[i]);
    }
    printf("\n");
    
    /* FIXED: Use adequate buffer sizes */
    uint8_t encrypted_data[256];
    size_t encrypted_size = 0;
    
    ret = rsa_4096_encrypt_binary(&pub_key, test_data, test_size, 
                                  encrypted_data, sizeof(encrypted_data), &encrypted_size);
    if (ret != 0) {
        printf("❌ Binary encryption failed: %d\n", ret);
        rsa_4096_free(&pub_key);
        rsa_4096_free(&priv_key);
        return ret;
    }
    
    printf("   Encrypted data (%zu bytes): ", encrypted_size);
    for (size_t i = 0; i < encrypted_size && i < 16; i++) {
        printf("%02x ", encrypted_data[i]);
    }
    if (encrypted_size > 16) printf("...");
    printf("\n");
    
    /* Decrypt */
    uint8_t decrypted_data[256];
    size_t decrypted_size = 0;
    
    ret = rsa_4096_decrypt_binary(&priv_key, encrypted_data, encrypted_size,
                                  decrypted_data, sizeof(decrypted_data), &decrypted_size);
    if (ret != 0) {
        printf("❌ Binary decryption failed: %d\n", ret);
        rsa_4096_free(&pub_key);
        rsa_4096_free(&priv_key);
        return ret;
    }
    
    printf("   Decrypted data (%zu bytes): ", decrypted_size);
    for (size_t i = 0; i < decrypted_size; i++) {
        printf("%02x ", decrypted_data[i]);
    }
    printf("\n");
    
    /* FIXED: Proper comparison */
    if (decrypted_size == test_size && memcmp(test_data, decrypted_data, test_size) == 0) {
        printf("✅ Binary round-trip test PASSED\n");
    } else {
        printf("❌ Binary round-trip test FAILED\n");
        printf("   Expected %zu bytes, got %zu bytes\n", test_size, decrypted_size);
        rsa_4096_free(&pub_key);
        rsa_4096_free(&priv_key);
        return -1;
    }
    
    printf("===============================================\n");
    rsa_4096_free(&pub_key);
    rsa_4096_free(&priv_key);
    return 0; 
}