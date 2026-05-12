CC = clang
CFLAGS = -g -Wall
CTESTFLAGS = -g -Wall
CLIBFLAGS = -g -Wall -I"$HOME/local/include" -L"$HOME/local/lib" -ldwarf -lelf

LOCAL = /home/murrayde/local
LIBDWARF_INC = -I$(LOCAL)/include
LIBDWARF_LIB = -L$(LOCAL)/lib -ldwarf -lelf


all: realerrors test_basic segfaulter segfaulter2 traceeLib.so

realerrors: realerrors.c symaddr.c symaddr.h
	$(CC) $(CFLAGS) -o realerrors realerrors.c symaddr.c

# traceeLib.so: traceeLib.c trace_symbolizer.c trace_symbolizer.h
# 	$(CC) $(CLIBFLAGS) -shared -fPIC -o traceeLib.so traceeLib.c trace_symbolizer.c

traceeLib.so: traceeLib.c trace_symbolizer.c trace_symbolizer.h memHelper.c memHelper.h
	$(CC) $(CFLAGS) $(LIBDWARF_INC) -fPIC -shared -Wl,-rpath,/home/murrayde/local/lib -o $@ traceeLib.c trace_symbolizer.c memHelper.c $(LIBDWARF_LIB)

test_basic: test_basic.c 
	$(CC) $(CTESTFLAGS) -o test_basic test_basic.c 

segfaulter: segfaulter.c 
	$(CC) $(CTESTFLAGS) -o segfaulter segfaulter.c

segfaulter2: segfaulter2.c 
	$(CC) $(CTESTFLAGS) -o segfaulter2 segfaulter2.c


clean:
	rm -f realerrors test_basic segfaulter segfaulter2 traceeLib.so

