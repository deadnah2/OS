# Makefile for Dynamic Loader Project

# Cross-compilation support
CROSS_COMPILE_SUFFIX ?= -linux-gnueabi
CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc

# Compiler flags
CFLAGS = -std=gnu99 -Wall -Werror -g -D_GNU_SOURCE
CFLAGS += -DPROG_HEADER=prog_header

# Output directory
OUT = out

# Architecture detection
ARCH = $(basename $(notdir $(wildcard arch/*.h)))
CHECK_ARCH = $(addprefix check_, $(ARCH))
CHECK_CC_ARCH = $(addprefix check_cc_, $(ARCH))

# Binary targets
BIN = $(OUT)/test_lib.so $(OUT)/loader

# Default target
all: $(BIN)

# Create output directory
$(OUT):
	@mkdir -p $(OUT)

# Build test_lib.o (object file)
$(OUT)/test_lib.o: test_lib.c | $(OUT)
	$(CC) $(CFLAGS) -fvisibility=hidden -shared -fPIC -c $< \
		-o $@ -MMD -MF $@.d

# Build test_lib.so (shared library)
$(OUT)/test_lib.so: $(OUT)/test_lib.o
	$(CC) -shared -Wl,--entry=prog_header -Wl,-z,defs -nostdlib \
		$< -o $@

# Build object files for loader
$(OUT)/%.o: %.c | $(OUT)
	$(CC) $(CFLAGS) -o $@ -MMD -MF $@.d -c $<

# Loader object files
LOADER_OBJS = $(OUT)/loader.o $(OUT)/test_loader.o

# Build final loader executable
$(OUT)/loader: $(LOADER_OBJS)
	$(CC) -o $@ $(LOADER_OBJS)

# Architecture check targets
$(CHECK_CC_ARCH)::
	@echo "Check cross compiler CROSS_COMPILE_SUFFIX=$(CROSS_COMPILE_SUFFIX) exist or not"
	@echo "If failed, please specify CROSS_COMPILE_SUFFIX"
	@which $(patsubst check_cc_%,%,$@)$(CROSS_COMPILE_SUFFIX)-gcc

# Clean target
clean:
	rm -rf $(OUT)

# Test target
test: $(BIN)
	cd $(OUT) && ./loader

# Debug target - show relocations
debug-reloc: $(OUT)/test_lib.so
	readelf -r $(OUT)/test_lib.so

# Debug target - show symbols
debug-syms: $(OUT)/test_lib.so
	readelf -s $(OUT)/test_lib.so

# Debug target - show headers
debug-headers: $(OUT)/test_lib.so
	readelf -h $(OUT)/test_lib.so

# Help target
help:
	@echo "Available targets:"
	@echo "  all          - Build all binaries (default)"
	@echo "  clean        - Remove build directory"
	@echo "  test         - Build and run test"
	@echo "  debug-reloc  - Show relocations in test_lib.so"
	@echo "  debug-syms   - Show symbols in test_lib.so"
	@echo "  debug-headers- Show ELF headers"
	@echo "  help         - Show this help"

# Include dependency files
-include $(OUT)/*.d

# Phony targets
.PHONY: all clean test debug-reloc debug-syms debug-headers help $(CHECK_CC_ARCH)