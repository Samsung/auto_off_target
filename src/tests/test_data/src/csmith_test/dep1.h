int dep1_function(int a);

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
};
