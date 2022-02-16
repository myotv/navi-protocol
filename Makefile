CC=gcc-6

.SUFFIXES: .c .o .cpp .h

CFLAGS=-MMD -O3 -march=broadwell  -funsigned-char -g -std=c11 -D_FILE_OFFSET_BITS=64 -Werror -D_GNU_SOURCE -fvisibility=hidden

all: test_client test_client1 test_client2 libnavi.a libnavi-test.a

-include $(wildcard *.d)

test_client: test_client.o libnavi-test.a -lcrypto -ljuice -lpthread

test_client1: test_client1.o libnavi-test.a libjuice-static.a -lcrypto  -lpthread

test_client2: test_client2.o libnavi-test.a libjuice-static.a -lcrypto  -lpthread

test_client.o: test_client.c

test_client1.o: test_client1.c

test_client2.o: test_client2.c

libnavi.a: libnavi.o encryption.o utils.o transport.o tlv.o perfcounters.o
	$(LD) -flto -r $^ -o libnavi_all.o
	ar crs $@ libnavi_all.o
	nm libnavi_all.o | grep ' T ' | cut -d\  -f 3 | grep -v '^navi_' | sed 's/^/-L /' | xargs objcopy libnavi.a

libnavi-test.a: libnavi.o encryption.o utils.o transport.o tlv.o perfcounters.o
	ar crs $@ $^

clean:
	rm -f *.o libnavi-test.a libnavi.a *.d test_client test_client1


-include .localtests
