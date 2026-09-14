.PHONY: all preload jail install test console-install

all: preload jail

preload:
	$(MAKE) -C preload

jail:
	$(MAKE) -C jail

install: preload jail
	python3 -m pip install -e ".[dev]"

test:
	python3 -m pytest

console-install:
	cd console && npm install
