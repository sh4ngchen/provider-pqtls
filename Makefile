# 设置 OpenSSL 路径（根据实际路径进行修改）
OPENSSL_ROOT_DIR = /usr/local/openssl3
OPENSSL_INCLUDE_DIR = $(OPENSSL_ROOT_DIR)/include
OPENSSL_LIB_DIR = $(OPENSSL_ROOT_DIR)/lib

# 编译器和标志
CC = gcc
#CFLAGS = -Wall -g -I/usr/include
CFLAGS += -I./libprov/include
#LDFLAGS = -L$(OPENSSL_LIB_DIR) -lssl -lcrypto

# 目标文件和输出
TARGET = provider.so
SRCS = src/provider.c
OBJS = $(SRCS:.c=.o)

# 编译目标
all: $(TARGET)

# 生成共享库
$(TARGET): $(OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# 编译 C 源文件
%.o: %.c
	$(CC) $(CFLAGS) -fPIC -o $@ -c $<

# 清理中间文件和目标文件
clean:
	rm -f $(OBJS) $(TARGET)

# 安装目标文件到系统
install: $(TARGET)
	cp $(TARGET) /usr/local/lib/openssl3

uninstall: $(TARGET)
	rm -f /usr/local/lib/openssl3/$(TARGET)

