# OpenSSL 3.0 Post-Quantum Provider Makefile

# 编译器和标志
CC = gcc
CFLAGS = -Wall -fPIC -I/usr/include/openssl -g -DDEBUG
LDFLAGS = -shared -lrandombytes -lpqcrystals_kyber512_ref -lpqcrystals_kyber768_ref -lpqcrystals_kyber1024_ref -lpqcrystals_kyber_fips202_ref -lpqcrystals_dilithium2_ref -lpqcrystals_dilithium3_ref -lpqcrystals_dilithium5_ref -lpqcrystals_dilithium_fips202_ref -lrandombytes -lcrypto

# 目录定义
SRC_DIR = .
BUILD_DIR = _build
OBJ_DIR = $(BUILD_DIR)/obj

# 源文件
SRC = $(wildcard impl/keymgmt/*.c) \
	  $(wildcard impl/encoder/*.c) \
	  $(wildcard impl/decoder/*.c) \
	  $(wildcard impl/kem/*.c) \
	  $(wildcard util/*.c) \
	  provider.c

# 目标文件
OBJ = $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC))

# 目标
TARGET = $(BUILD_DIR)/pqtls.so

# 默认目标
all: $(TARGET) $(RANDOMBYTES_TARGET)

# 创建构建目录
$(BUILD_DIR) $(OBJ_DIR):
	mkdir -p $@

# 编译共享库
$(TARGET): $(OBJ) | $(BUILD_DIR)
	$(CC) -o $@ $^ $(LDFLAGS)

# 编译规则
$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# 清理生成的文件
clean:
	rm -rf $(BUILD_DIR)

# 安装provider到系统目录
install: $(TARGET) $(RANDOMBYTES_TARGET)
	@echo "Installing PQTLS provider..."
	@mkdir -p /usr/local/lib64/ossl-modules
	@install -m 0755 $(TARGET) /usr/local/lib64/ossl-modules/pqtls.so
	@echo "Provider installed to /usr/local/lib64/ossl-modules/pqtls.so"
	@ldconfig
	@echo "If you use system OpenSSL, you may need change the install path to /usr/lib/x86_64-linux-gnu/ossl-modules/"
	@echo "To use the provider, ensure your OpenSSL configuration includes it."

# 卸载provider
uninstall:
	rm -f /usr/local/lib64/ossl-modules/pqtls.so
	ldconfig

.PHONY: all clean install uninstall
