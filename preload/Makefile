CC ?= gcc
CFLAGS ?= -shared -fPIC -O2
LDLIBS ?= -ldl

.PHONY: all install clean

all: libholdfast.so

# gcc -shared -fPIC -O2 -ldl -o libholdfast.so holdfast_preload.c
libholdfast.so: holdfast_preload.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

install: libholdfast.so
	@# Copy via a temp file so this succeeds when the build output
	@# already lives at /workspace/preload/libholdfast.so.
	cp -f libholdfast.so /workspace/preload/libholdfast.so.tmp
	mv -f /workspace/preload/libholdfast.so.tmp /workspace/preload/libholdfast.so

clean:
	rm -f libholdfast.so
