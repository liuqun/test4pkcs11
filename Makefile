# Encoding: UTF-8
# Top level Makefile for my sample program

.PHONY: all
all: src/config.mk
	$(MAKE) -C src --makefile=GNUmakefile

src/config.mk: configure
	$(MAKE) defconfig

configure: configure.ac
	autoreconf --install
	chmod +x ./configure

.PHONY: defconfig
defconfig:
	./configure

.PHONY: clean
clean: src/config.mk
	$(MAKE) -C src --makefile=GNUmakefile $@

.PHONY: distclean
distclean: clean
	$(RM) -r config.log config.status autom4te.cache
	$(RM) src/config.mk src/config.h
# vim: ts=4 sw=4
