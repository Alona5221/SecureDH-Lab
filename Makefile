CC=gcc
CFLAGS=-O2 -Wall -Wextra -Iinclude -pthread
LIBSRC=src/common.c src/net.c src/dh.c src/sha256.c src/hmac.c src/aes.c src/gcm.c src/kdf.c src/protocol.c src/auth.c src/log.c
.PHONY: all clean test
all: server client mitm keygen
server: src/server.c $(LIBSRC)
	$(CC) $(CFLAGS) -o $@ $^
client: src/client.c $(LIBSRC)
	$(CC) $(CFLAGS) -o $@ $^
mitm: src/mitm.c $(LIBSRC)
	$(CC) $(CFLAGS) -o $@ $^
keygen: src/keygen.c src/common.c
	$(CC) $(CFLAGS) -o $@ $^
test_crypto: tests/test_crypto.c $(LIBSRC)
	$(CC) $(CFLAGS) -o $@ $^
test_protocol: tests/test_protocol.c $(LIBSRC)
	$(CC) $(CFLAGS) -o $@ $^
test: all test_crypto test_protocol
	./test_crypto
	./test_protocol
clean:
	rm -f server client mitm keygen test_crypto test_protocol *.o psk.bin logs/*.log
