/**
 * OpenSSL 3.0 Provider - Caesar Cipher Implementation
 * 
 * 这个文件实现了一个简单的OpenSSL 3.0 provider，提供凯撒密码加密功能。
 * 凯撒密码是一种简单的替换密码，将字母表中的每个字母替换为其后的第n个字母。
 */

#include <string.h>
#include <openssl/core_names.h>
#include <openssl/core.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/core_dispatch.h>
#include "provider.h"

/* Provider 参数获取函数 */
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;

/* Provider 参数定义 */
static const OSSL_PARAM caesar_param_types[] = {
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, NULL, 0),
    OSSL_PARAM_END
};

/* Cipher 参数定义 */
static const OSSL_PARAM caesar_cipher_param_types[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
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

/* Cipher 参数获取函数 */
static OSSL_FUNC_cipher_get_params_fn cipher_get_params;
static int cipher_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, CAESAR_KEY_LENGTH))
        return 0;
    
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 0))
        return 0;
    
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, CAESAR_BLOCK_SIZE))
        return 0;

    return 1;
}

static OSSL_FUNC_cipher_get_ctx_params_fn cipher_get_ctx_params;
static int cipher_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, CAESAR_KEY_LENGTH))
        return 0;
    
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 0))
        return 0;
    
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, CAESAR_BLOCK_SIZE))
        return 0;

    return 1;
}

static OSSL_FUNC_cipher_gettable_params_fn cipher_gettable_params;
static const OSSL_PARAM *cipher_gettable_params(void *provctx)
{
    return caesar_cipher_param_types;
}

static const OSSL_PARAM *cipher_gettable_ctx_params(void *ctx)
{
    return caesar_cipher_param_types;
}

/* Caesar cipher 实现 */

/**
 * 创建新的凯撒密码上下文
 */
static OSSL_FUNC_cipher_newctx_fn caesar_newctx;
static void *caesar_newctx(void *provctx)
{
    CAESAR_CTX *ctx = OPENSSL_malloc(sizeof(CAESAR_CTX));
    if (ctx != NULL) {
        memset(ctx, 0, sizeof(CAESAR_CTX));
    }
    return ctx;
}

/**
 * 初始化凯撒密码加密
 * @param vctx 密码上下文
 * @param key 密钥（位移量）
 * @param keylen 密钥长度
 * @param iv 初始化向量（不使用）
 * @param ivlen 初始化向量长度
 * @param params 额外参数
 * @return 成功返回1，失败返回0
 */
static OSSL_FUNC_cipher_encrypt_init_fn caesar_encrypt_init;
static int caesar_encrypt_init(void *vctx, const unsigned char *key, size_t keylen,
                              const unsigned char *iv, size_t ivlen,
                              const OSSL_PARAM params[])
{
    CAESAR_CTX *ctx = (CAESAR_CTX *)vctx;
    
    if (ctx == NULL)
        return 0;
        
    if (key == NULL || keylen != CAESAR_KEY_LENGTH)
        return 0;
    
    ctx->shift = key[0];
    return 1;
}

/**
 * 执行凯撒密码加密
 * @param ctx 密码上下文
 * @param out 输出缓冲区
 * @param outl 输出长度
 * @param outsize 输出缓冲区大小
 * @param in 输入数据
 * @param inl 输入长度
 * @return 成功返回1，失败返回0
 */
static OSSL_FUNC_cipher_update_fn caesar_encrypt_update;
static int caesar_encrypt_update(void *ctx, unsigned char *out, size_t *outl,
                                size_t outsize, const unsigned char *in, size_t inl)
{
    CAESAR_CTX *cctx = (CAESAR_CTX *)ctx;
    size_t i;

    /* 基本参数检查 */
    if (cctx == NULL || in == NULL) {
        return 0;
    }

    /* 处理空输入 */
    if (inl == 0) {
        if (outl)
            *outl = 0;
        return 1;
    }

    /* 检查输出缓冲区大小 */
    if (out != NULL && outsize < inl) {
        return 0;
    }

    /* 如果只是查询需要的输出长度 */
    if (out == NULL) {
        if (outl)
            *outl = inl;
        return 1;
    }

    /* 执行凯撒加密 */
    for (i = 0; i < inl; i++) {
        if (in[i] >= 'A' && in[i] <= 'Z')
            out[i] = 'A' + ((in[i] - 'A' + cctx->shift) % 26);
        else if (in[i] >= 'a' && in[i] <= 'z')
            out[i] = 'a' + ((in[i] - 'a' + cctx->shift) % 26);
        else
            out[i] = in[i];
    }

    if (outl)
        *outl = inl;
    
    return 1;
}

/**
 * 完成凯撒密码加密
 * @param vctx 密码上下文
 * @param out 输出缓冲区
 * @param outl 输出长度
 * @param outsize 输出缓冲区大小
 * @return 成功返回1，失败返回0
 */
static OSSL_FUNC_cipher_final_fn caesar_encrypt_final;
static int caesar_encrypt_final(void *vctx, unsigned char *out, size_t *outl,
                               size_t outsize)
{
    if (outl)
        *outl = 0;
    return 1;
}

/**
 * 释放凯撒密码上下文
 */
static OSSL_FUNC_cipher_freectx_fn caesar_freectx;
static void caesar_freectx(void *vctx)
{
    CAESAR_CTX *ctx = (CAESAR_CTX *)vctx;
    OPENSSL_free(ctx);
}

/* Caesar cipher 函数表 */
static const OSSL_DISPATCH caesar_cipher_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))caesar_newctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))caesar_encrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))caesar_encrypt_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))caesar_encrypt_final },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))caesar_freectx },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))cipher_get_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))cipher_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))cipher_gettable_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))cipher_gettable_ctx_params },
    { 0, NULL }
};

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
    const OSSL_DISPATCH *i;

    /* 处理输入的dispatch表 */
    for (i = in; i->function_id != 0; i++) {
        switch (i->function_id) {
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(i);
            break;
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_FUNC_core_gettable_params(i);
            break;
        default:
            /* 忽略未知的函数ID */
            break;
        }
    }

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

