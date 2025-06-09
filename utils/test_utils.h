#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <stdint.h>
#include <stddef.h>

void print_hex(const char* label, const uint8_t* data, size_t length);
void print_test_header(const char* name);

#endif
