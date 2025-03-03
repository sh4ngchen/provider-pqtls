/**
 * OpenSSL 3.0 Provider - Provider Implementation
 * 
 * 这个文件实现了一个OpenSSL 3.0 provider，提供凯撒密码加密功能。
 */

#include <string.h>
#include <openssl/core_names.h>
#include <openssl/core.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/core_dispatch.h>
#include "implementations/include/implementations.h"
#include "implementations/cipher/caesar.h"

typedef struct {
    const OSSL_CORE_HANDLE *handle;  /* OpenSSL核心句柄 */
    OSSL_LIB_CTX *libctx;            /* 库上下文 */
} PROV_CTX;

/* Provider 参数定义 */
static const OSSL_PARAM caesar_param_types[] = {
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, NULL, 0),
    OSSL_PARAM_END
};

/* Provider 参数获取函数 */
static const OSSL_PARAM *caesar_gettable_params(void *provctx)
{
    return caesar_param_types;
}

static OSSL_FUNC_provider_get_params_fn caesar_get_params;
static int caesar_get_params(void *provctx, OSSL_PARAM params[])
{
    static const char name[] = "Caesar Provider";
    static const char version[] = "1.0.0";
    static const char buildinfo[] = "Caesar Provider v1.0.0";
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, name))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, version))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, buildinfo))
        return 0;
    return 1;
}

/* Provider 实现 */
static const OSSL_ALGORITHM provider_ciphers[] = {
    { "CAESAR", "provider=caesar", caesar_cipher_functions, "Caesar Cipher Implementation" },
    { NULL, NULL, NULL, NULL }
};

/**
 * 查询provider支持的算法
 */
static const OSSL_ALGORITHM *local_query(void *provctx, int operation_id,
                                     int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_CIPHER:
        return provider_ciphers;
    }
    return NULL;
}

/**
 * 清理provider上下文
 */
static void local_teardown(void *provctx)
{
    PROV_CTX *ctx = (PROV_CTX *)provctx;
    OPENSSL_free(ctx);
}

/* Provider 入口点 */
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                      const OSSL_DISPATCH *in,
                      const OSSL_DISPATCH **out,
                      void **provctx)
{
    PROV_CTX *ctx;

    /* 创建provider上下文 */
    ctx = OPENSSL_malloc(sizeof(PROV_CTX));
    if (ctx == NULL)
        return 0;

    ctx->handle = handle;

    /* 设置provider函数表 */
    static const OSSL_DISPATCH provider_functions[] = {
        { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))local_teardown },
        { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))local_query },
        { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))caesar_get_params },
        { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))caesar_gettable_params },
        { 0, NULL }
    };
    *out = provider_functions;
    *provctx = ctx;

    return 1;
}

