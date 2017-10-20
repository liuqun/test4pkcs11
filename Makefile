# Encoding: UTF-8
# Top level Makefile for my sample program

.PHONY: all
all: src/config.mk
	$(MAKE) -C src --makefile=GNUmakefile

src/config.mk: configure
	./configure

configure: configure.ac
	autoreconf --install
	chmod +x ./configure

clean:
	$(MAKE) -C src --makefile=GNUmakefile $@
	$(RM) src/config.mk src/config.h
# vim: ts=4 sw=4
