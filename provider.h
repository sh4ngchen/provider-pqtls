/**
 * OpenSSL 3.0 Provider - Caesar Cipher Header
 * 
 * 这个文件定义了凯撒密码provider的数据结构和常量。
 */

#ifndef PROVIDER_H
#define PROVIDER_H

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>

/**
 * Provider 上下文结构体
 */
typedef struct {
    const OSSL_CORE_HANDLE *handle;  /* OpenSSL核心句柄 */
    OSSL_LIB_CTX *libctx;            /* 库上下文 */
} PROV_CTX;

/**
 * Caesar cipher 上下文结构体
 */
typedef struct {
    int shift;              /* 位移量 */
    unsigned char *key;     /* 密钥 */
    size_t keylen;          /* 密钥长度 */
} CAESAR_CTX;

/* Cipher 参数常量 */
#define CAESAR_KEY_LENGTH 1    /* 凯撒密码密钥长度（1字节） */
#define CAESAR_BLOCK_SIZE 1    /* 凯撒密码块大小（1字节） */

#endif /* PROVIDER_H */ 