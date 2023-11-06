CC = gcc
CFLAGS = -w
objects = test_program.o dep1.o dep2.o

.PHONY: all clean

all: test_program

clean:
	rm -f test_program
	rm -f $(objects)

test_program: $(objects)
	$(CC) -o test_program $(objects)

%.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@
