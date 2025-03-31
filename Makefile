# OpenSSL 3.0 Post-Quantum Provider Makefile

# 编译器和标志
CC = gcc
CFLAGS = -Wall -fPIC -I/usr/include/openssl -g -DDEBUG
LDFLAGS = -shared -L/root/projects/kyber/ref/lib -lpqcrystals_kyber512_ref -lpqcrystals_kyber768_ref -lpqcrystals_kyber1024_ref -lpqcrystals_fips202_ref -lcrypto

# 目录定义
SRC_DIR = .
BUILD_DIR = _build
OBJ_DIR = $(BUILD_DIR)/obj

# 源文件
SRC = $(wildcard implementations/keymgmt/*.c) \
	  $(wildcard implementations/encoder/*.c) \
	  $(wildcard implementations/decoder/*.c) \
	  provider.c

# 目标文件
OBJ = $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC))

# 目标
TARGET = $(BUILD_DIR)/pqtls.so

# 默认目标
all: $(TARGET)

# 创建构建目录
$(BUILD_DIR) $(OBJ_DIR):
	mkdir -p $@

# 编译共享库
$(TARGET): $(OBJ) | $(BUILD_DIR)
	$(CC) -o $@ $^ $(LDFLAGS)

# 编译规则
$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	@mkdir -p $(dir $@)  # 添加这行以确保目录存在
	$(CC) $(CFLAGS) -c $< -o $@

# 清理生成的文件
clean:
	rm -rf $(BUILD_DIR)

# 安装provider到系统目录
install: $(TARGET)
	@echo "Installing PQTLS provider..."
	@mkdir -p /usr/local/lib64/ossl-modules
	@install -m 0755 $(TARGET) /usr/local/lib64/ossl-modules/pqtls.so
	@echo "Provider installed to /usr/local/lib64/ossl-modules/pqtls.so"
	@echo "To use the provider, ensure your OpenSSL configuration includes it."

# 卸载provider
uninstall:
	rm -f /usr/local/lib64/ossl-modules/pqtls.so

.PHONY: all clean install uninstall
