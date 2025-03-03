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

/* 辅助函数 */
int update_iv(CAESAR_CTX *ctx);

#endif /* CAESAR_H */ 