LIBEXT=$(shell r2 -HR2_LIBEXT)
CFLAGS+=$(shell pkg-config --cflags r_io r_socket)
CFLAGS+=-Isrc
LDFLAGS+=$(shell pkg-config --libs r_io r_socket)
R2_USER_PLUGINS=$(shell r2 -HR2_USER_PLUGINS)

BUILD_DIR=build
IO_RENEF=$(BUILD_DIR)/io_renef.$(LIBEXT)

SRCS=src/io_renef.c src/renef_socket.c src/renef_commands.c src/renef_memory.c
OBJS=$(SRCS:src/%.c=$(BUILD_DIR)/%.o)

all: $(BUILD_DIR) $(IO_RENEF)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

$(IO_RENEF): $(OBJS)
	$(CC) $(LDFLAGS) -shared -fPIC -o $(IO_RENEF) $(OBJS)

clean:
	rm -rf $(BUILD_DIR)

user-install install:
	mkdir -p $(R2_USER_PLUGINS)
	cp -f $(IO_RENEF) $(R2_USER_PLUGINS)

user-uninstall uninstall:
	rm -f $(R2_USER_PLUGINS)/io_renef.$(LIBEXT)
