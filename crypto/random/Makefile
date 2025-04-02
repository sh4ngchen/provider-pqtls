# 定义编译器
CC = gcc

# 编译选项，-fPIC用于生成位置无关代码，这是共享库所必需的
CFLAGS = -fPIC -Wall -Wextra -O2

# 定义目标和依赖
TARGET = librandombytes.so
SRC = randombytes.c

# 默认目标
all: $(TARGET)

# 编译共享库
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -shared -o $@ $<

# 清理规则
clean:
	rm -f $(TARGET)

.PHONY: all clean
