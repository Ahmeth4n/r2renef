LIBEXT=$(shell r2 -HR2_LIBEXT)
R2_CFLAGS=$(shell pkg-config --cflags r_io)
R2_LDFLAGS=$(shell pkg-config --libs r_io)
R2_USER_PLUGINS=$(shell r2 -HR2_USER_PLUGINS)

CFLAGS?=-O2 -g
CFLAGS+=-Wall -Isrc
LDLIBS+=-lpthread

BUILD_DIR=build
IO_RENEF=$(BUILD_DIR)/io_renef.$(LIBEXT)

# renef_proto.c and renef_socket.c do not use radare2: the unit tests link
# them on their own.
SRCS=src/io_renef.c src/renef_session.c src/renef_memory.c src/renef_maps.c \
     src/renef_commands.c src/renef_proto.c src/renef_socket.c
OBJS=$(SRCS:src/%.c=$(BUILD_DIR)/%.o)
HDRS=$(wildcard src/*.h)

TEST_PROTO=$(BUILD_DIR)/test_proto
TEST_SOCKET=$(BUILD_DIR)/test_socket

all: $(IO_RENEF)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: src/%.c $(HDRS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(R2_CFLAGS) -fPIC -c $< -o $@

$(IO_RENEF): $(OBJS)
	$(CC) $(LDFLAGS) -shared -fPIC -o $(IO_RENEF) $(OBJS) $(R2_LDFLAGS) $(LDLIBS)

$(TEST_PROTO): tests/test_proto.c src/renef_proto.c $(HDRS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ tests/test_proto.c src/renef_proto.c

$(TEST_SOCKET): tests/test_socket.c src/renef_proto.c src/renef_socket.c $(HDRS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ tests/test_socket.c src/renef_proto.c src/renef_socket.c $(LDLIBS)

# Unit tests: no radare2, no device.
unit: $(TEST_PROTO) $(TEST_SOCKET)
	$(TEST_PROTO)
	$(TEST_SOCKET)

# Drives the real r2 binary with the freshly built plugin (loaded with -l,
# nothing is installed) against tests/mock_renef_server.py on a spare port.
integration: $(IO_RENEF)
	python3 tests/integration_test.py --plugin $(IO_RENEF)

test check: unit integration

clean:
	rm -rf $(BUILD_DIR)

user-install install: $(IO_RENEF)
	mkdir -p $(R2_USER_PLUGINS)
	cp -f $(IO_RENEF) $(R2_USER_PLUGINS)

user-uninstall uninstall:
	rm -f $(R2_USER_PLUGINS)/io_renef.$(LIBEXT)

.PHONY: all unit integration test check clean install user-install uninstall user-uninstall
