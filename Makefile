.SUFFIXES: .c .o .cpp .h
.PHONY: all clean

CFLAGS=-MMD -O3 -funsigned-char -g -std=c11 -D_FILE_OFFSET_BITS=64 -Werror -D_GNU_SOURCE -fvisibility=hidden

-include .localsetup

TESTS=

#test_client test_client1 test_client2

all: libnavi.a libnavi-test.a tests

-include $(wildcard *.d)

libnavi.a: libnavi.o encryption.o utils.o transport.o tlv.o perfcounters.o navi-compat.o
	$(LD) -flto -r $^ -o libnavi_all.o
	ar crs $@ libnavi_all.o
	nm libnavi_all.o | grep ' T ' | cut -d\  -f 3 | grep -v '^navi_' | sed 's/^/-L /' | xargs objcopy libnavi.a

libnavi-test.a: libnavi.o encryption.o utils.o transport.o tlv.o perfcounters.o navi-compat.o
	ar crs $@ $^

clean:
	rm -f *.o libnavi-test.a libnavi.a *.d test_client test_client1


-include .localtests

tests: $(TESTS)
