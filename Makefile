CC = clang
CFLAGS = -g -Wall -no-pie


all: realerrors test_basic segfaulter

realerrors: realerrors.c
	$(CC) $(CFLAGS) -o realerrors realerrors.c

test_basic: test_basic.c 
	$(CC) $(CFLAGS) -o test_basic test_basic.c 

segfaulter: segfaulter.c 
	$(CC) $(CFLAGS) -o segfaulter segfaulter.c


clean:
	rm -f realerrors test_basic segfaulter

