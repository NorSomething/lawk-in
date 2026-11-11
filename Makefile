CC ?= cc
PKG_CONFIG ?= pkg-config
CFLAGS ?= -O2 -Wall -Wextra
CPPFLAGS += $(shell $(PKG_CONFIG) --cflags libnftables)
LDLIBS += $(shell $(PKG_CONFIG) --libs libnftables)

TARGET := lawk-in
SOURCES := src/main.c src/config.c src/resolver.c src/firewall.c
OBJECTS := $(SOURCES:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS) $(LDLIBS)

src/%.o: src/%.c include/common.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJECTS) $(TARGET)
