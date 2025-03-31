# 后量子加密 TLS Provider

## 项目概述

本项目开发一个支持后量子加密算法的OpenSSL Provider，实现在TLS协议中的应用。项目目前专注于：

**Kyber后量子密钥加密算法**: 实现抵御量子计算攻击的密钥交换方案

## 当前实现内容

- **密钥管理(keymgmt)**: 实现Kyber密钥对的生成、导入、导出和管理
- **编码/解码(encoder/decoder)**: 实现Kyber密钥的编解码

## 代码结构

```
.
├── crypto
│   └── kyber  --from https://github.com/pq-crystals/kyber with minor changes
├── implementations
│   ├── decoder
│   │   └── kyber_decoder.c
│   ├── encoder
│   │   └── kyber_encoder.c
│   ├── include
│   │   ├── api.h
│   │   ├── implementations.h
│   │   └── kyber.h
│   └── keymgmt
│       ├── kyber_keymgmt_1024.c
│       ├── kyber_keymgmt_512.c
│       └── kyber_keymgmt_768.c
├── Makefile
├── provider.c
└── README.md
```

## 构建指南

```bash
# 克隆仓库
git clone https://github.com/sh4ngchen/provider-pqtls.git

# 进入项目目录
cd provider-pqtls

# 编译并安装
make && make install
```

## 使用指南

### Provider查询

```bash
# 查询已加载的Provider
openssl list -providers -provider pqtls

# 查看Provider提供的密钥管理算法
openssl list -key-managers -provider pqtls
```

### Kyber密钥操作

```bash
# 生成Kyber密钥对
openssl genpkey -provider default -provider pqtls -algorithm KYBER512 -out kyber512.pem

# 查看密钥信息
目前不支持-text输出

# 从密钥提取公钥
openssl pkey -provider default -provider pqtls -in kyber512.pem -pubout -out kyber512.pub
```

## 开发路线图

- [√] 实现Kyber密钥管理(keymgmt)模块
- [√] 实现Kyber密钥编码/解码模块
- [ ] 实现Kyber密钥封装机制(KEM)
- [ ] 实现Crystals-Dilithium后量子数字签名算法
- [ ] 与TLS握手协议集成
- [ ] 进行性能测试与安全分析
- [ ] 完善文档和示例

## 依赖条件

- OpenSSL 3.0或更高版本
- GCC或Clang编译器
- [Kyber](https://github.com/pq-crystals/kyber)

## 贡献指南

欢迎提交Pull Request或创建Issue。

## 许可证

[待定]
