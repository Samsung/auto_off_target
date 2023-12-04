#include "dep1.h"

int dep1_function(int a, struct test_struct b, int __attribute__((vector_size (16))) c) {
    return a + b.member3;
}
