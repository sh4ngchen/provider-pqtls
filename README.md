# 后量子加密TLS Provider项目

## 项目概述

本项目旨在实现一个支持后量子加密算法的OpenSSL Provider，使其能够在TLS协议中使用。项目分为两个主要部分：

1. **Caesar加密Provider实现**：作为学习OpenSSL Provider架构的入门练习
2. **后量子加密算法Provider实现**：项目的最终目标

## Caesar加密Provider

Caesar加密Provider是一个简单的示例实现，目的是熟悉OpenSSL Provider的开发流程和架构。虽然Caesar加密算法本身不安全（仅作为教学示例），但通过实现这个简单的Provider，我们可以学习：

- Provider的基本结构
- 如何注册和实现加密算法
- 如何与OpenSSL核心API交互
- Provider的编译和加载过程

### 文件结构

- `caesar.h` 和 `caesar.c`: Caesar加密算法的实现
- `provider.h` 和 `provider.c`: Provider框架的实现
- `Makefile`: 编译脚本

### 编译方法

```bash
make
```

### 使用方法

```bash
# 加载Provider示例
openssl list -providers -provider-path ./ -provider provider

# 查看可用的加密算法
openssl list -cipher-algorithms -provider-path ./ -provider provider

# 使用Caesar加密示例（无需密码提示）
openssl enc -provider-path ./ -provider provider -provider default -caesar -e -nosalt -nopad -k "A" -in plaintext.txt -out ciphertext.txt

# 解密示例
openssl enc -provider-path ./ -provider provider -provider default -caesar -d -nosalt -nopad -k "A" -in ciphertext.txt -out decrypted.txt
```

**注意:** 
1. `-provider provider`使用您的自定义provider
2. `-provider default`同时加载默认provider，提供SHA256等哈希算法
3. `-nosalt -nopad`避免使用盐值和填充
4. `-k "A"`提供一个固定密码，其中"A"的ASCII值将作为Caesar加密的位移量

### 测试示例

创建一个测试文件：
```bash
echo "HELLO WORLD" > plaintext.txt

# 加密（使用位移量1）
openssl enc -provider-path ./ -provider provider -provider default -caesar -e -nosalt -nopad -k "A" -in plaintext.txt -out ciphertext.txt

# 查看加密结果
cat ciphertext.txt  # 应该显示 "IFMMP XPSME"

# 解密
openssl enc -provider-path ./ -provider provider -provider default -caesar -d -nosalt -nopad -k "A" -in ciphertext.txt -out decrypted.txt

# 验证解密结果
cat decrypted.txt  # 应该显示原始文本 "HELLO WORLD"
```

## 后量子加密算法Provider

这是项目的最终目标，将实现一个或多个后量子加密算法，并使其能够在TLS协议中使用。

### 计划实现的功能

- 后量子密钥交换算法
- 后量子数字签名算法
- TLS握手协议的集成
- 性能测试和安全分析

## 依赖

- OpenSSL 3.0+
- C编译器 (gcc/clang)

## 许可证

[待定]