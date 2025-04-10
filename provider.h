#ifndef PROVCTX_H
#define PROVCTX_H
#include <openssl/types.h>
#include <openssl/core.h>

/* Provider Context 相关声明 */
typedef struct prov_ctx_st {
    const OSSL_CORE_HANDLE *handle;  /* OpenSSL核心句柄 */
    OSSL_LIB_CTX *libctx;            /* 库上下文 */
} PROV_CTX;

/* Provider Context 工具函数 */
OSSL_LIB_CTX *PROV_CTX_get0_libctx(const PROV_CTX *ctx);

int provider_get_capabilities(void *provctx, const char *capability, OSSL_CALLBACK *cb, void *arg);

#endif