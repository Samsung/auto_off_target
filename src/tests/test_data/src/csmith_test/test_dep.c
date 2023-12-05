#include "test_dep.h"

int test_function(int a, struct test_struct b, test_vector c,
                  enum forward_enum * d) {
    return a + b.member3 + c[0] + (long)d;
}

int test(int argc, char ** argv) {
    test_vector t = {0};
    test_function(10, test_global, t, forward_enum_global);
    return csmith_main(argc, argv);
}

