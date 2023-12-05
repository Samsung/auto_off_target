CC = gcc
CFLAGS = -w
objects = test_program.o csmith_dep.o test_dep.o

.PHONY: all clean

all: test_program

clean:
	rm -f test_program
	rm -f $(objects)

test_program: $(objects)
	$(CC) -o test_program $(objects)

%.o : %.c %.h
	$(CC) -c $(CFLAGS) $< -o $@
