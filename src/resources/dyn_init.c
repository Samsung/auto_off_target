/* Auto off-target PoC

 Copyright Samsung Electronics
 Samsung Mobile Security Team @ Samsung R&D Poland
*/ 


#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Despite the name, this header supports C as well */
#include <unflatten.hpp>


/* Headers for functions from auto-generated file fptr_stub.c.template */
void initialize_function_pointer_stubs(void);
void aot_kflat_initialize_global_variables(void);
void* fptrstub_search(const char* symbol);

/* Just a simple wrapper to match function prototype with the one expected by unflatten_load*/
static uintptr_t get_fpointer_test_function_address(const char* fsym) {
	return (uintptr_t) fptrstub_search(fsym);
}

/* KFLAT library wrappers */
static CUnflatten unflatten = NULL;

void aot_kflat_init(const char* imgpath) {
	int ret;

	if(unflatten != NULL) {
		fprintf(stderr, "Stay where you are! For some reason aot_kflat_init was invoked twice.\n");
		fprintf(stderr, "Such scenario is impossible to happen in non-modified off-target!\n");
		fprintf(stderr, "\nWhatever you're doing, please remember to call aot_kflat_fini!!\n");
		assert(unflatten != NULL);
	}

	FILE* in = fopen(imgpath, "r");
	if(in == NULL) {
		fprintf(stderr, "[!!!] Error: Dynamic-init failed to open flatten image '%s'\n", imgpath);
		fprintf(stderr, "This off-target has been built with --dynamic-init option enabled\n");
		fprintf(stderr, " and therefore requires a valid flatten image to be provided.\n");
		fprintf(stderr, "Please generate and copy memory dump to file flat.img in CWD\n");
		assert(in != NULL);
	}

	/* Setup function pointers now, as they are required for loading kflat image */
	initialize_function_pointer_stubs();

	unflatten = unflatten_init(0);
	assert(unflatten != NULL);

	ret = unflatten_load(unflatten, in, get_fpointer_test_function_address);
	assert(ret == 0);

	/* Setup globals after flattened image with their content has been loaded */
	aot_kflat_initialize_global_variables();

	fclose(in);
}

void aot_kflat_fini(void) {
	unflatten_deinit(unflatten);
	unflatten = NULL;
}

void* aot_kflat_root_by_name(const char* name, unsigned long* size) {
	return unflatten_root_pointer_named(unflatten, name, size);
}
