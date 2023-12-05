#ifndef TEST_DEP_H
#define TEST_DEP_H

#include "csmith_dep.h"

typedef int test_vector __attribute__ ((vector_size (16)));

enum forward_enum;

struct test_struct {
    struct {
        int a;
        int b;
    } member1[1];

    struct {
        int a;
        int b;
    } **member2[0];

    int member3;

    int __attribute__ ((vector_size (16))) member4;

    test_vector member5;
};

static struct test_struct test_global = {
        .member1 = {{ .a = 1, .b = 2, }},
        .member2 = {},
        .member3 = 2137,
        .member4 = { 2, 1, 3, 7 },
        .member5 = { 1, 3, 3, 7},
};

static enum forward_enum * forward_enum_global;

int test_function(int a, struct test_struct b, test_vector c,
                  enum forward_enum * e);

int test(int argc, char ** argv);

#endif
