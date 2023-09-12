# AOT generated this (beautiful) makefile.
# Copyright Samsung Electronics

# Thanks to http://nuclear.mutantstargoat.com/articles/make/#a-makefile-for-99-of-your-programs :)

# src => source files, obj => object files
src = $(wildcard *.c)
obj = $(src:.c=.o)
lib := 
extra_bc :=

CLANG_TIDY:=clang-tidy
CLANG_TIDY_OPTS:= --checks="-*,readability-function-size" --config="{Checks: 'readability-function-size',CheckOptions: [{key: readability-function-size.BranchThreshold, value: '0'},{key: readability-function-size.NestingThreshold, value: '0'},{key: readability-function-size.LineThreshold, value: '0'},{key: readability-function-size.StatementThreshold, value: '0'}]}"

CFLAGS = -MD
LDFLAGS = 
COMP = clang


################################
# Cross-compilation support
################################
ARCH := x86_64
ifneq (, $(filter $(ARCH),arm64 aarch64))
  # Cross-compiled libc for arm64 is available in packet "libc6-dev-arm64-cross"
  CFLAGS += -target aarch64-linux-gnu -isystem /usr/aarch64-linux-gnu/include --static
  ARCH = arm64
else ifeq ($(ARCH),)
else ifeq ($(ARCH), x86_64)
else
$(error Unsupported architecture selected, please use x86_64 or arm64)
endif


################################
# Dynamic Init support (KFLAT)
################################
ifneq ($(wildcard dyn_init.c), )

  ifeq (${KFLAT_LIB_PATH},)
    $(error This off-target has been built with --dynamic-init option enabled. \
      Please setup env KFLAT_LIB_PATH to point to the directory with built \
      Unflatten library (ex. kflat_repo/lib))
  endif

  $(info [AoT] Building off-target with dynamic init support (--dynamic-init flag))

  lib += ${KFLAT_LIB_PATH}/libunflatten_${ARCH}.a
  CFLAGS += -I${KFLAT_LIB_PATH} -L${KFLAT_LIB_PATH} -fPIC
  LDFLAGS += -lstdc++
  extra_bc += $(wildcard ${KFLAT_LIB_PATH}/*.bc)
endif


.DEFAULT_GOAL:= native

%.o : %.c
	$(COMP) -g $(CFLAGS) -o $@ -c $<

# native: the default linux native target
.PHONY: native
native: CFLAGS+=-ferror-limit=0 -fno-integrated-cc1 -MD
native: $(obj) $(lib)
	$(COMP) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# stats: a target for clang-tidy to get some complexity stats
.PHONY: stats
stats:
	$(CLANG_TIDY) $(src) $(CLANG_TIDY_OPTS)

# as native but should work with clang < 10.0
.PHONY: native-old
native-old: CFLAGS+=-ferror-limit=0 -MD
native-old: $(obj) $(lib)
	$(COMP) -o $@ $^ $(LDFLAGS)

# as native but compiled using gcc
.PHONY: native-gcc
native-gcc:  COMP=gcc
native-gcc: CFLAGS+=-fmax-errors=0 -MD -fPIE
native-gcc: $(obj) $(lib)
	$(COMP) -o $@ $^ $(LDFLAGS)

# address sanitizer
.PHONY: asan
asan: CFLAGS+=-fsanitize=address -MD
asan: $(obj) $(lib)
	$(COMP) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# memory sanitizer
.PHONY: msan
msan: CFLAGS+=-fsanitize=memory -MD
msan: $(obj) $(lib)
	$(COMP) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# undefined behaviour sanitizer
.PHONY: ubsan
ubsan: CFLAGS+=-fsanitize=undefined -MD
ubsan: $(obj) $(lib)	
	$(COMP) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# data flow sanitizer
# aot_dsan.c.lib contains the callbacks which can't be instrumented with dfsan and is compiled separately
.PHONY: dfsan
dfsan: CFLAGSDFSAN=-fno-sanitize=dataflow -MD -mllvm -dfsan-event-callbacks -g -DDFSAN -fPIE
dfsan: CFLAGS=-fsanitize=dataflow -MD -mllvm -dfsan-event-callbacks -g -DDFSAN -I${KFLAT_LIB_PATH} -fsanitize-ignorelist=dfsan_ignore_list.txt
dfsan: COMP=clang-15
dfsan: $(obj) $(lib)	
	cp aot_dfsan.c.lib aot_dfsan.c
	$(COMP) $(CFLAGSDFSAN) -c -o aot_dfsan.o aot_dfsan.c
	rm aot_dfsan.c
	$(COMP) $(CFLAGS) -o $@ $^ aot_dfsan.o $(LDFLAGS)

# AFL
.PHONY: afl
afl: export AFL_USE_ASAN=1
#afl: export AFL_HARDEN=1
ifeq ($(shell which afl-clang-lto),)
afl: COMP=afl-clang-fast
else
afl: COMP=afl-clang-lto
endif
afl: COMP+=-DAFL
afl: $(obj) $(lib)
	$(COMP) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# KLEE
.PHONY: klee
klee: CFLAGS+=-emit-llvm -DKLEE -MD -w
klee: COMP=clang-13
klee: LD=llvm-link-13
klee: $(obj)
	$(LD) -o $@.bc $^ $(extra_bc)


# SYMCC
.PHONY: symcc
symcc: COMP=symcc
symcc: COMP+=-DAFL
symcc: $(obj) $(lib)
	$(COMP) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	mkdir -p "symcc_results"


# code coverage
.PHONY: gcov
gcov: CFLAGS+=-fprofile-instr-generate -fcoverage-mapping -MD
gcov: $(obj) $(lib)
	$(COMP) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# for debugging purposes - optimizations off
.PHONY: debug
debug: CFLAGS+=-ferror-limit=0 -g -O0 -MD
debug: $(obj) $(lib)
	$(COMP) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# for generating on-device PoCs
.PHONY: recall
recall: CFLAGS+=-DAOT_RECALL_BINARY -g
recall: $(obj) $(lib)
	$(COMP) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(obj) aot_dfsan.o native *.d

# thanks to https://nathandumont.com/blog/automatically-detect-changes-in-header-files-in-a
-include $(obj:.o=.d)
