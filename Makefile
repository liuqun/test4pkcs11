# Encoding: UTF-8
# Makefile for my sample program
# https://github.com/opencryptoki/opencryptoki/blob/e460cc1ab72b3b27e648ff883b74bac0733c71af/doc/opencryptoki-howto.md#10-appendix-a-sample-program

EXEC += test
EXEC += print-current-tokens
CUSTOMIZED_INCLUDE_DIRS =
CFLAGS += -g -O0 $(CUSTOMIZED_INCLUDE_DIRS)
CXXFLAGS += -g -O0 $(CUSTOMIZED_INCLUDE_DIRS)
LIBS += -ldl -lpthread

.PHONY: all
all: config.h $(EXEC)

print-current-tokens: print-current-tokens.o pkcs11-api-loader.o
	$(LINK.o) -o $@ $^ $(LIBS)

test: test.o pkcs11-api-loader.o ApplicationResourceRecorder.o
	$(LINK.o) -o $@ $^ $(LIBS) -lstdc++

%.o: %.cpp %.h
	$(COMPILE.cpp) -o $@ $<

%.o: %.cpp
	$(COMPILE.cpp) -o $@ $<

%: %.c
	$(LINK.c) -o $@ $^ $(LIBS)

%.o: %.c %.h
	$(COMPILE.c) -o $@ $<

%.o: %.c
	$(COMPILE.c) -o $@ $<

.PHONY: clean
clean:
	$(RM) $(EXEC)

config.h:
	$(MAKE) defconfig

.PHONY: defconfig
defconfig:
	autoreconf --install
	chmod +x ./configure
	./configure
# vim: ts=4 sw=4
