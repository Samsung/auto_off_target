#include "dep1.h"
#include "dep2.h"

struct test_struct test_global = {
        .member1 = {{ .a = 1, .b = 2, }},
        .member2 = {},
        .member3 = 2137,
        .member4 = { 2, 1, 3, 7 },
};

int test(int argc, char ** argv){
    test_vector t = {0};
    dep1_function(10, test_global, t);
    return csmith_main(argc, argv);
}

int main(int argc, char ** argv) {
    return test(argc, argv);
}
