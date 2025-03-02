# OpenSSL 3.0 Caesar Cipher Provider Makefile

# 编译器和标志
CC = gcc
CFLAGS = -Wall -fPIC -I/usr/include/openssl
LDFLAGS = -lcrypto

# 目标文件
PROVIDER_OBJ = provider.o caesar.o
TEST_OBJ = test.o

# 目标
all: provider.so test

# 编译provider共享库
provider.so: $(PROVIDER_OBJ)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# 编译测试程序
test: $(TEST_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

# 编译.c文件为.o文件
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 运行测试
run-test: all
	./test

# 清理生成的文件
clean:
	rm -f *.o *.so test

# 安装provider到系统目录
install: provider.so
	mkdir -p /usr/lib/openssl/providers
	cp provider.so /usr/lib/openssl/providers/caesar.so

# 卸载provider
uninstall:
	rm -f /usr/lib/openssl/providers/caesar.so

# 依赖关系
provider.o: provider.c provider.h caesar.h
caesar.o: caesar.c caesar.h
test.o: test.c

.PHONY: all clean install uninstall run-test

