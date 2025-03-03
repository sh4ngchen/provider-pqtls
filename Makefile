# OpenSSL 3.0 Caesar Cipher Provider Makefile

# 编译器和标志
CC = gcc
CFLAGS = -Wall -fPIC -I/usr/include/openssl
LDFLAGS = -lcrypto

# 目录定义
SRC_DIR = .
BUILD_DIR = _build
OBJ_DIR = $(BUILD_DIR)/obj

# 目标文件
PROVIDER_OBJ = $(OBJ_DIR)/provider.o $(OBJ_DIR)/caesar.o
TEST_OBJ = $(OBJ_DIR)/test_caesar.o

# 目标
all: $(BUILD_DIR)/caesar.so $(BUILD_DIR)/test_caesar

# 创建构建目录
$(BUILD_DIR) $(OBJ_DIR):
	mkdir -p $@

# 编译provider共享库
$(BUILD_DIR)/caesar.so: $(PROVIDER_OBJ) | $(BUILD_DIR)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# 编译测试程序
$(BUILD_DIR)/test_caesar: $(TEST_OBJ) $(BUILD_DIR)/caesar.so | $(BUILD_DIR)
	$(CC) -o $@ $^ $(LDFLAGS)

# 编译.c文件为.o文件
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/caesar.o: implementations/cipher/caesar.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/test_caesar.o: test/test_caesar.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# 运行测试
run-test: all
	$(BUILD_DIR)/test_caesar

# 清理生成的文件
clean:
	rm -rf $(BUILD_DIR)

# 安装provider到系统目录
install: $(BUILD_DIR)/caesar.so
	mkdir -p /usr/local/lib64/ossl-modules
	cp $(BUILD_DIR)/caesar.so /usr/local/lib64/ossl-modules/caesar.so

# 卸载provider
uninstall:
	rm -f /usr/local/lib64/ossl-modules/caesar.so

# 依赖关系
$(OBJ_DIR)/provider.o: provider.c implementations/include/implementations.h
$(OBJ_DIR)/caesar.o: implementations/cipher/caesar.c implementations/cipher/caesar.h implementations/include/implementations.h
$(OBJ_DIR)/test_caesar.o: test/test_caesar.c

.PHONY: all clean install uninstall run-test