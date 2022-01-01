CC ?= cc
STND ?= -ansi -pedantic
CFLAGS += $(STND) -O2 -Wall -Wextra -Wunreachable-code -ftrapv \
        -D_POSIX_C_SOURCE=2
PREFIX=/usr/local

all: pcips

pcips_deps=src/main.o src/apply.o src/create.o src/join.o
pcips: $(pcips_deps)
	$(CC) -o $@ $(pcips_deps)

install: pcips
	install -m755 pcips $(PREFIX)/bin/pcips
	install -m644 man/man1/pcips.1 $(PREFIX)/share/man/man1/

clean:
	rm -rf src/*.o pcips
