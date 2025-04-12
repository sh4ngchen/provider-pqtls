# Provider-Post-Quantum-TLS

## 项目概述

一个支持后量子加密算法并适配TLS协议的OpenSSL Provider

## 代码结构

```bash
.
├── crypto
│   ├── kyber  # from https://github.com/pq-crystals/kyber
│   ├── dilithium  # from https://github.com/pq-crystals/dilithium
│   └── random  # extract from kyber&dilithium
├── impl  # 实现
│   ├── kem
│   ├── sign
│   ├── encoder
│   ├── decoder
│   ├── keymgmt
│   ├── include
│   └── prov_capabilities.c # 注册TLS所需的 groups & sigalgs
├── util  # 工具
│   ├── x509.c # 读取x509密钥的唯一办法？copy from openssl
│   └── util.h
├── provider.h
├── provider.c
├── Makefile
├── README.md
├── fullbuild.sh  # 编译安装kyber, dilithium, random, 本项目
└── clean.sh  # 清理编译文件
```

## 构建指南

```bash
# 构建安装openssl 3.4
git clone https://github.com/openssl/openssl && cd openssl
git checkout openssl-3.4.0
./config -d '-Wl,--enable-new-dtags,-rpath,$(LIBRPATH)'
make -j$(nproc) && make install

# 自行清理旧版本openssl，注意清理include文件

# 克隆仓库
git clone https://github.com/sh4ngchen/provider-pqtls.git

# 进入项目目录
cd provider-pqtls

# 编译安装
./fullbuild.sh

# 清理编译文件
./clean.sh
```

## 使用指南

### 配置openssl.cnf

```bash
openssl version -d
# OPENSSLDIR: "/usr/local/ssl"
```

修改`/OPENSSLDIR/openssl.cnf`
```ini
[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
pqtls = pqtls_sect

[default_sect]
activate = 1

[pqtls_sect]
activate = 1
module = /usr/local/lib64/ossl-modules/pqtls.so
```

不修改也可在运行命令时添加 `-provider default -provider pqtls` 选项

### Provider查询

```bash
# 查询已加载的Provider
openssl list -providers

# 查看Provider提供的算法
openssl list -key-managers | grep pqtls
openssl list -encoders | grep pqtls
openssl list -decoders | grep pqtls
openssl list -kem-algorithms | grep pqtls
openssl list -signature-algorithms | grep pqtls 
```

### Kyber密钥操作

```bash
# 生成Kyber密钥对并输出公钥
openssl genpkey -algorithm kyber512 -out kyber512.pem -outpubkey kyber512.pub

# 输出der格式
openssl genpkey -algorithm kyber512 -out kyber512.der -outform DER

# 查看密钥信息
目前不支持-text输出
openssl asn1prase -in kyber512.pem

# 从密钥提取公钥
openssl pkey -in kyber512.pem -pubout -out kyber512.pub
```

### Kyber Kem

```bash
# 生成shared secret和cipher text
openssl pkeyutl -encap -inkey kyber512.pub -pubin -secret kyber512.ss1 -out kyber512.ct

# 使用私钥从cipher text提取 是shared secret
openssl pkeyutl -decap -inkey kyber512.pem -in kyber512.ct -out kyber512.ss2

# 查看shared secret
cat kyber512.ss1 | od -tx1 && cat kyber512.ss2 | od -tx1
```

### Dilithium Sign

```bash
# 生成密钥
openssl genpkey -algorithm dilithium3 -out dilithium3.pem -outpubkey dilithium3.pub

# 私钥签名
openssl dgst -sha256 -sign dilithium3.pem -signature dilithium3.sig message.txt

# 公钥验签
openssl dgst -sha256 -verify dilithium3.pub -signature dilithium3.sig message.txt
```

### Generate CRT

```bash
# 生成crt证书
openssl req -x509 -new -key dilithium2.pem -out dilithium2.crt -days 365 \
  -subj "/CN=PQ-TLS Test Server" \
  -addext "keyUsage=digitalSignature" \
  -addext "basicConstraints=CA:FALSE"
```

### Test s_server

```bash
# 启动s_server(default port: 4433)
openssl s_server -cert dilithium2.crt -key dilithium2.pem -groups kyber512 -sigalgs dilithium2 -www -tls1_3

# 启动s_client
openssl s_client -connect localhost:4433 -groups kyber512 -sigalgs dilithium2 -CAfile dilithium2.crt
```

## TODO List

- [x] 实现`Kyber keymgmt`
- [x] 实现`Kyber encoder/decoder`
- [x] 实现`Kyber kem`
- [x] 实现`Dilithium keymgmt/encoder/decoder`
- [x] 实现`Dilithium signature`
- [x] 使用`openssl req`生成`crt`证书
- [x] 注册`groups`和`sigalgs`
- [x] 适配`s_server`与`s_client`功能
- [ ] 进行性能测试
- [ ] 完善文档和示例

## Requirements

- [OpenSSL 3.4+](https://github.com/openssl/openssl/tree/openssl-3.4.0)
- [Kyber](https://github.com/pq-crystals/kyber)
- [Dilithium](https://github.com/pq-crystals/dilithium)

## 贡献指南

欢迎提交Pull Request或创建Issue。

## 许可证

[待定]
