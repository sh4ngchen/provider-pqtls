/**
 * OpenSSL 3.0 Provider - Caesar Cipher Header
 * 
 * 这个文件定义了凯撒密码算法的数据结构和函数声明。
 */

#ifndef CAESAR_H
#define CAESAR_H

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/err.h>

/* Cipher 参数常量 */
#define CAESAR_KEY_LENGTH 1    /* 凯撒密码密钥长度（1字节） */
#define CAESAR_BLOCK_SIZE 1    /* 凯撒密码块大小（1字节） */

/* 错误代码 */
#define CAESAR_R_INVALID_KEY_LENGTH     1
#define CAESAR_R_INVALID_OPERATION      2
#define CAESAR_R_OUTPUT_BUFFER_TOO_SMALL 3
#define CAESAR_R_CIPHER_OPERATION_FAILED 4

/* IV状态 */
typedef enum {
    IV_STATE_UNINITIALISED,
    IV_STATE_BUFFERED,
    IV_STATE_COPIED,
    IV_STATE_FINISHED
} IV_STATE;

/**
 * Caesar cipher 上下文结构体
 */
typedef struct {
    /* 基本参数 */
    int enc;                /* 1表示加密，0表示解密 */
    size_t keylen;          /* 密钥长度 */
    size_t ivlen;           /* IV长度（不使用，但需要兼容接口） */
    unsigned char iv[16];   /* IV缓冲区（不使用，但需要兼容接口） */
    unsigned char oiv[16];  /* 原始IV（不使用，但需要兼容接口） */
    
    /* 算法特定参数 */
    int shift;              /* 位移量 */
    unsigned char *key;     /* 密钥 */
    
    /* 状态管理 */
    int key_set;            /* 密钥是否已设置 */
    IV_STATE iv_state;      /* IV状态 */
    
    /* 数据缓冲区 */
    unsigned char data_buf[CAESAR_BLOCK_SIZE]; /* 数据缓冲区 */
    size_t data_buf_len;                       /* 数据缓冲区长度 */
    
    /* 上下文 */
    void *provctx;          /* Provider上下文 */
} CAESAR_CTX;

/* 函数声明 */
void *caesar_newctx(void *provctx);
void *caesar_dupctx(void *ctx);
int caesar_encrypt_init(void *vctx, const unsigned char *key, size_t keylen,
                       const unsigned char *iv, size_t ivlen,
                       const OSSL_PARAM params[]);
int caesar_decrypt_init(void *vctx, const unsigned char *key, size_t keylen,
                       const unsigned char *iv, size_t ivlen,
                       const OSSL_PARAM params[]);
int caesar_update(void *ctx, unsigned char *out, size_t *outl,
                 size_t outsize, const unsigned char *in, size_t inl);
int caesar_final(void *vctx, unsigned char *out, size_t *outl,
                size_t outsize);
int caesar_cipher(void *vctx, unsigned char *out, size_t *outl,
                 size_t outsize, const unsigned char *in, size_t inl);
void caesar_freectx(void *vctx);

/* 参数函数 */
int cipher_get_params(OSSL_PARAM params[]);
int cipher_get_ctx_params(void *vctx, OSSL_PARAM params[]);
int cipher_set_ctx_params(void *vctx, const OSSL_PARAM params[]);
const OSSL_PARAM *cipher_gettable_params(void *provctx);
const OSSL_PARAM *cipher_gettable_ctx_params(void *ctx);
const OSSL_PARAM *cipher_settable_ctx_params(void *ctx);

/* 辅助函数 */
int update_iv(CAESAR_CTX *ctx);

extern const OSSL_DISPATCH caesar_cipher_functions[];

#endif /* CAESAR_H */ 