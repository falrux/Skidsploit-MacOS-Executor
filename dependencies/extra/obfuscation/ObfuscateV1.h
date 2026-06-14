#pragma once
#include <cstring>

// Compile-time string passthrough (no obfuscation)
#define OBF(x)        (x)
#define OBFUSCATE(x)  (x)

static inline int inline_strcmp(const char* a, const char* b) {
    while (*a && *a == *b) { ++a; ++b; }
    return (unsigned char)*a - (unsigned char)*b;
}
