.PHONY: all preload install test console-install

all: preload

preload:
	$(MAKE) -C preload

install: preload
	python3 -m pip install -e ".[dev]"

test:
	python3 -m pytest

console-install:
	cd console && npm install
