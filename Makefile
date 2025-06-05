# Makefile cho dự án Dynamic Loader

# Hỗ trợ cross-compilation
CROSS_COMPILE_SUFFIX ?= -linux-gnueabi
CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc

# Cờ compiler
CFLAGS = -std=gnu99 -Wall -Werror -g -D_GNU_SOURCE
CFLAGS += -DPROG_HEADER=prog_header

# Thư mục đầu ra
OUT = out

# Phát hiện kiến trúc
ARCH = $(basename $(notdir $(wildcard arch/*.h)))
CHECK_ARCH = $(addprefix check_, $(ARCH))
CHECK_CC_ARCH = $(addprefix check_cc_, $(ARCH))

# Các file binary đích
BIN = $(OUT)/test_lib.so $(OUT)/loader

# Target mặc định
all: $(BIN)

# Tạo thư mục đầu ra
$(OUT):
	@mkdir -p $(OUT)

# Build test_lib.o (file object)
$(OUT)/test_lib.o: test_lib.c | $(OUT)
	$(CC) $(CFLAGS) -fvisibility=hidden -shared -fPIC -c $< \
		-o $@ -MMD -MF $@.d

# Build test_lib.so (shared library)
$(OUT)/test_lib.so: $(OUT)/test_lib.o
	$(CC) -shared -Wl,--entry=prog_header -Wl,-z,defs -nostdlib \
		$< -o $@

# Build các file object cho loader
$(OUT)/%.o: %.c | $(OUT)
	$(CC) $(CFLAGS) -o $@ -MMD -MF $@.d -c $<

# Các file object của Loader
LOADER_OBJS = $(OUT)/loader.o $(OUT)/test_loader.o

# Build file thực thi loader cuối cùng
$(OUT)/loader: $(LOADER_OBJS)
	$(CC) -o $@ $(LOADER_OBJS)

# Các target kiểm tra kiến trúc
$(CHECK_CC_ARCH)::
	@echo "Kiểm tra cross compiler CROSS_COMPILE_SUFFIX=$(CROSS_COMPILE_SUFFIX) có tồn tại hay không"
	@echo "Nếu thất bại, vui lòng chỉ định CROSS_COMPILE_SUFFIX"
	@which $(patsubst check_cc_%,%,$@)$(CROSS_COMPILE_SUFFIX)-gcc

# Target dọn dẹp
clean:
	rm -rf $(OUT)

# Test target
test: $(BIN)
	cd $(OUT) && ./loader

# Target debug - hiển thị relocations
debug-reloc: $(OUT)/test_lib.so
	readelf -r $(OUT)/test_lib.so

# Target debug - hiển thị symbols
debug-syms: $(OUT)/test_lib.so
	readelf -s $(OUT)/test_lib.so

# Target debug - hiển thị headers
debug-headers: $(OUT)/test_lib.so
	readelf -h $(OUT)/test_lib.so

# Target trợ giúp
help:
	@echo "Available targets:"
	@echo "  all          - Build all binaries (default)"
	@echo "  clean        - Remove build directory"
	@echo "  test         - Build and run test"
	@echo "  debug-reloc  - Show relocations in test_lib.so"
	@echo "  debug-syms   - Show symbols in test_lib.so"
	@echo "  debug-headers- Show ELF headers"
	@echo "  help         - Show this help"

# Bao gồm các file dependency
-include $(OUT)/*.d

# Phony targets
.PHONY: all clean test debug-reloc debug-syms debug-headers help $(CHECK_CC_ARCH)