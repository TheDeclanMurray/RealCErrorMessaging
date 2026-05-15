CC = clang
CFLAGS = -g -Wall
CTESTFLAGS = -g -Wall
CLIBFLAGS = -g -Wall -I"$HOME/local/include" -L"$HOME/local/lib" -ldwarf -lelf

LOCAL = /home/murrayde/local
LIBDWARF_INC = -I$(LOCAL)/include
LIBDWARF_LIB = -L$(LOCAL)/lib -ldwarf -lelf

all: realerrors testSuite traceeLib.so overhead lkbug

realerrors: realerrors.c symaddr.c symaddr.h
	$(CC) $(CFLAGS) -o realerrors realerrors.c symaddr.c

traceeLib.so: traceeLib.c trace_symbolizer.c trace_symbolizer.h memHelper.c memHelper.h
	$(CC) $(CFLAGS) $(LIBDWARF_INC) -fPIC -shared -Wl,-rpath,/home/murrayde/local/lib -o $@ traceeLib.c trace_symbolizer.c memHelper.c $(LIBDWARF_LIB)

testSuite: testSuite.c 
	$(CC) $(CTESTFLAGS) -o testSuite testSuite.c

overhead: overhead.c
	$(CC) $(CTESTFLAGS) -o overhead overhead.c

lkbug: linuxKernelBug.c
	$(CC) $(CTESTFLAGS) -o lkbug linuxKernelBug.c

clean:
	rm -f realerrors testSuite traceeLib.so overhead lkbug

