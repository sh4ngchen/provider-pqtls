# 后量子加密TLS Provider项目

## 项目概述

本项目旨在实现一个支持后量子加密算法的OpenSSL Provider，使其能够在TLS协议中使用。项目分为两个主要部分：

1. **Caesar加密Provider实现**：作为学习OpenSSL Provider架构的入门练习
2. **后量子加密算法Provider实现**：项目的最终目标

### 文件结构

- `caesar.h` 和 `caesar.c`: Caesar加密算法的实现
- `provider.h` 和 `provider.c`: Provider框架的实现
- `Makefile`: 编译脚本

### Build

```bash
git clone https://github.com/sh4ngchen/provider-pqtls.git && cd provider-pqtls
make && make install
```

### 使用方法

```bash
# 加载Provider示例
openssl list -providers -provider caesar

# 查看可用的加密算法
openssl list -cipher-algorithms -provider caesar

# 使用Caesar加密
openssl enc -provider provider -caesar -e -in plaintext.txt -out ciphertext.txt -K 03
# 或者
echo "Hello World\!" | openssl enc -provider provider -e -caesar -K 03

# 解密示例
openssl enc -provider provider -caesar -d -in ciphertext.txt -out decrypted.txt -K 03
# 或者
echo "Khoor Zruog\!" | openssl enc -provider provider -d -caesar -K 03
```

### TODO

- 后量子密钥交换算法(Kyber)
- 后量子数字签名算法(Crystals-Dilithium)
- TLS握手协议的集成
- 性能测试和安全分析

## 依赖

- OpenSSL 3.0+
- C编译器 (gcc/clang)

## 许可证

[待定]
