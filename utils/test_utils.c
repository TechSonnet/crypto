#include "test_utils.h"
#include <stdio.h>

void print_hex(const char* label, const uint8_t* data, size_t length) {
    printf("%s: ", label);
    for (size_t i = 0; i < length; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

void print_test_header(const char* name) {
    printf("\n=== %s ===\n", name);
}

void print_hex_compact(const char* label, const uint8_t* data, size_t len) {
    printf("%s:", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

void print_keystream(const char* label, const uint32_t* data, size_t count) {
    printf("%s:", label);
    for (size_t i = 0; i < count; i++) {
        printf("%08X", data[i]);
    }
    printf("\n");
}