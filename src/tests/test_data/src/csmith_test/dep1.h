typedef int test_vector __attribute__ ((vector_size (16)));

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

int dep1_function(int a, struct test_struct b, test_vector c);
