# AOT generated this (beautiful) makefile.
# Copyright Samsung Electronics

# Thanks to http://nuclear.mutantstargoat.com/articles/make/#a-makefile-for-99-of-your-programs :)

# src => source files, obj => object files
src = $(wildcard *.c)
obj = $(src:.c=.o)

CLANG_TIDY:=/media/storage/toolchain_6305083/out_release/stage2-install/bin/clang-tidy
CLANG_TIDY_OPTS:= --checks="-*,readability-function-size" --config="{Checks: 'readability-function-size',CheckOptions: [{key: readability-function-size.BranchThreshold, value: '0'},{key: readability-function-size.NestingThreshold, value: '0'},{key: readability-function-size.LineThreshold, value: '0'},{key: readability-function-size.StatementThreshold, value: '0'}]}"

CFLAGS = -MD
COMP = clang

# modify build flags based on selected architecture
ifneq (, $(filter $(ARCH),arm64 aarch64))
	# Cross-compiled libc for arm64 is available in packet "libc6-dev-arm64-cross"
	CFLAGS += -target aarch64-linux-gnu -isystem /usr/aarch64-linux-gnu/include --static
else ifeq ($(ARCH),)
else ifeq ($(ARCH), x86_64)
# ignore x86_64
else
$(error Unsupported architecture selected, please use x86_64 or arm64)
endif

.DEFAULT_GOAL:= native

%.o : %.c
	$(COMP) -g $(CFLAGS) -o $@ -c $<

# native: the default linux native target
.PHONY: native
native: CFLAGS+=-ferror-limit=0 -fno-integrated-cc1 -MD -w
native: $(obj)
	$(COMP) $(CFLAGS) -o $@ $^ 

# stats: a target for clang-tidy to get some complexity stats
.PHONY: stats
stats:
	$(CLANG_TIDY) $(src) $(CLANG_TIDY_OPTS)

# as native but should work with clang < 10.0
.PHONY: native-old
native-old: CFLAGS+=-ferror-limit=0 -MD -w
native-old: $(obj)
	$(COMP) -o $@ $^ 

# address sanitizer
.PHONY: asan
asan: CFLAGS+=-fsanitize=address -MD -w 
asan: $(obj)
	$(COMP) $(CFLAGS) -o $@ $^

# memory sanitizer
.PHONY: msan
msan: CFLAGS+=-fsanitize=memory -MD -w
msan: $(obj)
	$(COMP) $(CFLAGS) -o $@ $^

# undefined behaviour sanitizer
.PHONY: ubsan
ubsan: CFLAGS+=-fsanitize=undefined -MD -w
ubsan: $(obj)	
	$(COMP) $(CFLAGS) -o $@ $^

# data flow sanitizer
# aot_dsan.c.lib contains the callbacks which can't be instrumented with dfsan and is compiled separately
.PHONY: dfsan
dfsan: CFLAGSDFSAN=-fno-sanitize=dataflow -MD -w -mllvm -dfsan-event-callbacks -g -DDFSAN -fPIE
dfsan: CFLAGS=-fsanitize=dataflow -MD -w -mllvm -dfsan-event-callbacks -g -DDFSAN
dfsan: COMP=clang-15
dfsan: $(obj)	
	cp aot_dfsan.c.lib aot_dfsan.c
	$(COMP) $(CFLAGSDFSAN) -c -o aot_dfsan.o aot_dfsan.c
	rm aot_dfsan.c
	$(COMP) $(CFLAGS) -o $@ $^ aot_dfsan.o

# AFL
.PHONY: afl
afl: export AFL_USE_ASAN=1
#afl: export AFL_HARDEN=1
ifeq ($(shell which afl-clang-lto),)
afl: COMP=afl-clang-fast
else
afl: COMP=afl-clang-lto
endif
afl: COMP+=-DAFL -w
afl: $(obj)
	$(COMP) $(CFLAGS) -o $@ $^

# KLEE
.PHONY: klee
klee: CFLAGS+=-emit-llvm -DKLEE -MD -w
klee: COMP=clang-9
klee: LD=llvm-link-9
klee: $(obj)
	$(LD) -o $@.bc $^

# code coverage
.PHONY: gcov
gcov: CFLAGS+=-fprofile-instr-generate -fcoverage-mapping -MD -w
gcov: $(obj)
	$(COMP) $(CFLAGS) -o $@ $^

# for debugging purposes - optimizations off
.PHONY: debug
debug: CFLAGS+=-ferror-limit=0 -g -O0 -MD
debug: $(obj)
	$(COMP) $(CFLAGS) -o $@ $^

# for generating on-device PoCs
.PHONY: recall
recall: CFLAGS+=-DAOT_RECALL_BINARY -g -w
recall: $(obj)
	$(COMP) $(CFLAGS) -o $@ $^

.PHONY: clean
clean:
	rm -f $(obj) aot_dfsan.o native *.d

# thanks to https://nathandumont.com/blog/automatically-detect-changes-in-header-files-in-a
-include $(obj:.o=.d)
