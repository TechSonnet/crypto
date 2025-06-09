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
