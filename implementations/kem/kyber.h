/**
 * OpenSSL 3.0 Provider - Kyber KEM Header
 * 
 * 这个文件定义了Kyber密钥封装机制(KEM)算法的数据结构和函数声明。
 * Kyber是一种后量子密码学算法，基于模格问题的安全性。
 */

#ifndef KYBER_H
#define KYBER_H

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include "kyber/ref/api.h"  /* 添加 pq-crystals/kyber 的头文件 */

/* Kyber 参数常量 */
#define KYBER_512_SECRET_KEY_LENGTH 1632    /* Kyber-512 私钥长度 */
#define KYBER_512_PUBLIC_KEY_LENGTH 800     /* Kyber-512 公钥长度 */
#define KYBER_512_CIPHERTEXT_LENGTH 768     /* Kyber-512 密文长度 */
#define KYBER_512_SHARED_SECRET_LENGTH 32   /* Kyber-512 共享密钥长度 */

#define KYBER_768_SECRET_KEY_LENGTH 2400    /* Kyber-768 私钥长度 */
#define KYBER_768_PUBLIC_KEY_LENGTH 1184    /* Kyber-768 公钥长度 */
#define KYBER_768_CIPHERTEXT_LENGTH 1088    /* Kyber-768 密文长度 */
#define KYBER_768_SHARED_SECRET_LENGTH 32   /* Kyber-768 共享密钥长度 */

#define KYBER_1024_SECRET_KEY_LENGTH 3168   /* Kyber-1024 私钥长度 */
#define KYBER_1024_PUBLIC_KEY_LENGTH 1568   /* Kyber-1024 公钥长度 */
#define KYBER_1024_CIPHERTEXT_LENGTH 1568   /* Kyber-1024 密文长度 */
#define KYBER_1024_SHARED_SECRET_LENGTH 32  /* Kyber-1024 共享密钥长度 */

/* Kyber 安全级别 */
typedef enum {
    KYBER_512,   /* 安全级别1 (AES-128等同) */
    KYBER_768,   /* 安全级别3 (AES-192等同) */
    KYBER_1024   /* 安全级别5 (AES-256等同) */
} KYBER_SECURITY_LEVEL;

/**
 * Kyber KEM 上下文结构体
 */
typedef struct {
    /* 基本参数 */
    KYBER_SECURITY_LEVEL security_level;  /* 安全级别 */
    size_t secret_key_len;                /* 私钥长度 */
    size_t public_key_len;                /* 公钥长度 */
    size_t ciphertext_len;                /* 密文长度 */
    size_t shared_secret_len;             /* 共享密钥长度 */
    
    /* 密钥材料 */
    unsigned char *secret_key;            /* 私钥 */
    unsigned char *public_key;            /* 公钥 */
    
    /* 状态管理 */
    int key_set;                          /* 密钥是否已设置 */
    
    /* 上下文 */
    void *provctx;                        /* Provider上下文 */
} KYBER_CTX;

#endif /* KYBER_H */
