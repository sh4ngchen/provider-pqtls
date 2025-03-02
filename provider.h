/**
 * OpenSSL 3.0 Provider - Provider Header
 * 
 * 这个文件定义了provider的数据结构和常量。
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

#endif /* PROVIDER_H */ 