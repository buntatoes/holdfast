CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2
BIN ?= holdfast-jail

.PHONY: all install clean

all: $(BIN)

$(BIN): holdfast_jail.c
	$(CC) $(CFLAGS) -o $@ $<

install: $(BIN)
	cp -f $(BIN) /workspace/jail/$(BIN).tmp
	mv -f /workspace/jail/$(BIN).tmp /workspace/jail/$(BIN)

clean:
	rm -f $(BIN)
