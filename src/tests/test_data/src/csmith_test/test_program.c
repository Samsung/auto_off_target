#include "dep1.h"
#include "dep2.h"

int test(int argc, char ** argv){
    dep1_function(10);
    return csmith_main(argc, argv);
}

int main(int argc, char ** argv) {
    return test(argc, argv);
}
