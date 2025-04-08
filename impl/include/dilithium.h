#ifndef DILITHIUM_H
#define DILITHIUM_H

#include "../../crypto/dilithium/ref/api.h"
#include "../../provider.h"

/* 定义Dilithium的临时OID */
#define OID_dilithium2 "1.3.6.1.4.1.2.267.7.4.4"
#define OID_dilithium3 "1.3.6.1.4.1.2.267.7.6.5"
#define OID_dilithium5 "1.3.6.1.4.1.2.267.7.8.7"

/* OSSL参数最大大小定义 */
#define OSSL_MAX_NAME_SIZE 50
#define OSSL_MAX_PROPQUERY_SIZE 256

/* DILITHIUM_KEY 结构体定义 */
typedef struct {
    OSSL_LIB_CTX *libctx;
    unsigned char *public_key;
    unsigned char *secret_key;
    size_t public_key_len;    /* 公钥长度 */
    size_t secret_key_len;   /* 私钥长度 */
    size_t sig_len;       /* 签名长度 */
    int has_public;      /* 是否有公钥 */
    int has_private;     /* 是否有私钥 */
    int references;
    int version;
    char *tls_name;
} DILITHIUM_KEY;

/* 签名上下文结构 */
typedef struct {
    PROV_CTX *provctx;
    DILITHIUM_KEY *pkey;         /* 当前签名使用的密钥 */
    
    /* 算法参数 */
    unsigned char *aid;
    size_t aidlen;               /* AID长度 */
    
    /* 摘要相关 */
    EVP_MD *md;                  /* 消息摘要算法 */
    EVP_MD_CTX *mdctx;           /* 消息摘要上下文 */
    size_t mdsize;               /* 消息摘要大小 */
    char mdname[OSSL_MAX_NAME_SIZE]; /* 摘要算法名称 */
    
    /* 签名相关 */
    unsigned char *sig;          /* 签名缓冲区 */
    size_t siglen;               /* 签名长度 */
    
    /* 待签名/验证数据 */
    unsigned char *tbs;          /* 待签名数据 */
    size_t tbslen;               /* 待签名数据长度 */
    
    /* 属性查询 */
    char *propq;                 /* 属性查询字符串 */
    
    /* 上下文状态 */
    int operation;               /* 操作类型 */
    unsigned int flag_allow_md:1;/* 是否允许更改MD */
} DILITHIUM_SIGN_CTX;

/* DILITHIUM_GEN_CTX 结构体定义 */
typedef struct {
    void *provctx;
    DILITHIUM_KEY *key;
    int selection;
    int version;
} DILITHIUM_GEN_CTX;

/* Decoder context */
typedef struct {
    char *keytype_name;
    OSSL_LIB_CTX *libctx;
} DILITHIUM_DECODER_CTX;

/* Encoder context */
typedef struct {
    OSSL_LIB_CTX *libctx;
    int only_pub; // 1：只编码公钥
} DILITHIUM_ENCODER_CTX;

#endif // DILITHIUM_H