# Holdfast Jail — proprietary. Not Apache-2.0. See LICENSE.
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -fno-strict-aliasing
CPPFLAGS ?=
LDFLAGS ?=

.PHONY: all clean install

all: holdfast-jail

# Kernel jail supervisor: user/mount/pid/uts/ipc (+optional net) namespaces,
# Landlock, seccomp-bpf, no_new_privs. Composes with libholdfast.so.
holdfast-jail: holdfast_jail.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS)

install: holdfast-jail
	install -m 0755 holdfast-jail /usr/local/bin/holdfast-jail

clean:
	rm -f holdfast-jail
