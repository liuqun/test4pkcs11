# Encoding: UTF-8
# Makefile for my sample program

include config.mk

EXEC += test
EXEC += print-current-tokens
CUSTOMIZED_INCLUDE_DIRS =
CFLAGS += -g -O0 $(CUSTOMIZED_INCLUDE_DIRS)
CXXFLAGS += -g -O0 $(CUSTOMIZED_INCLUDE_DIRS)
LIBS += -ldl -lpthread

.PHONY: all
all: config.h $(EXEC)

print-current-tokens: print-current-tokens.o pkcs11-probe.o
	$(LINK.o) -o $@ $^ $(LIBS)

test: test.o symbol-from-rc.o pkcs11-probe.o ApplicationResourceRecorder.o
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
	$(RM) $(EXEC) *.o

# vim: ts=4 sw=4
