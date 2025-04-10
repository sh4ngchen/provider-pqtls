/**
 * OpenSSL 3.0 Provider - Kyber KEM 实现
 * 
 * 这个文件实现了Kyber-512/768/1024的密钥封装机制(KEM)功能
 */

#include <string.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/evp.h>
#include "../include/impl.h"
#include "../include/kyber.h"

/* 函数声明 */
static OSSL_FUNC_kem_newctx_fn kyber_kem_newctx;
static OSSL_FUNC_kem_freectx_fn kyber_kem_freectx;
static OSSL_FUNC_kem_dupctx_fn kyber_kem_dupctx;
static OSSL_FUNC_kem_encapsulate_init_fn kyber_kem_init;
static OSSL_FUNC_kem_encapsulate_fn kyber_kem_encapsulate;
static OSSL_FUNC_kem_decapsulate_fn kyber_kem_decapsulate;
static OSSL_FUNC_kem_gettable_ctx_params_fn kyber_kem_gettable_ctx_params;
static OSSL_FUNC_kem_get_ctx_params_fn kyber_kem_get_ctx_params;
static OSSL_FUNC_kem_settable_ctx_params_fn kyber_kem_settable_ctx_params;
static OSSL_FUNC_kem_set_ctx_params_fn kyber_kem_set_ctx_params;

/* 创建新的KEM上下文 */
static void *kyber_kem_newctx(void *provctx)
{
    KYBER_KEM_CTX *kctx;

    if ((kctx = OPENSSL_zalloc(sizeof(*kctx))) == NULL)
        return NULL;
    
    kctx->provctx = provctx;
    kctx->pkey = NULL;

    return kctx;
}

/* 释放KEM上下文 */
static void kyber_kem_freectx(void *ctx)
{
    KYBER_KEM_CTX *kctx = (KYBER_KEM_CTX *)ctx;
    
    if (kctx == NULL)
        return;
    OPENSSL_free(kctx);
}

/* 复制KEM上下文 */
static void *kyber_kem_dupctx(void *ctx)
{
    KYBER_KEM_CTX *src = (KYBER_KEM_CTX *)ctx;
    KYBER_KEM_CTX *dst;

    if (src == NULL)
        return NULL;
    
    if ((dst = OPENSSL_zalloc(sizeof(*dst))) == NULL)
        return NULL;
    
    *dst = *src;
    
    return dst;
}

/* 初始化KEM操作 */
static int kyber_kem_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    KYBER_KEM_CTX *kctx = (KYBER_KEM_CTX *)ctx;

    if (kctx == NULL || provkey == NULL)
        return 0;
    
    kctx->pkey = provkey;
    
    return 1;
}

/* 密钥封装 - 生成共享密钥和密文 */
static int kyber_kem_encapsulate(void *ctx, unsigned char *out, size_t *outlen,
                           unsigned char *secret, size_t *secretlen)
{
    KYBER_KEM_CTX *kctx = (KYBER_KEM_CTX *)ctx;
    KYBER_KEY *key;
    unsigned char *pubkey;
    int version;
    int ret = 0;
    
    if (kctx == NULL)
        return 0;
        
    key = kctx->pkey;
    if (key == NULL || key->public_key == NULL)
        return 0;
    
    version = key->version;
    pubkey = key->public_key;
    
    /* 根据安全级别处理不同逻辑 */
    switch (version) {
    case 512:
        /* 验证输出缓冲区大小 */
        if (out == NULL || secret == NULL) {
            *outlen = pqcrystals_kyber512_CIPHERTEXTBYTES;
            *secretlen = pqcrystals_kyber512_BYTES;
            return 1;
        }
        
        if (*outlen < pqcrystals_kyber512_CIPHERTEXTBYTES ||
            *secretlen < pqcrystals_kyber512_BYTES) {
            return 0;
        }
        
        /* 执行Kyber-512密钥封装 */
        pqcrystals_kyber512_ref_enc(out, secret, pubkey);
        
        *outlen = pqcrystals_kyber512_CIPHERTEXTBYTES;
        *secretlen = pqcrystals_kyber512_BYTES;
        ret = 1;
        break;

    case 768:
        /* 验证输出缓冲区大小 */
        if (out == NULL || secret == NULL) {
            *outlen = pqcrystals_kyber768_CIPHERTEXTBYTES;
            *secretlen = pqcrystals_kyber768_BYTES;
            return 1;
        }
        
        if (*outlen < pqcrystals_kyber768_CIPHERTEXTBYTES ||
            *secretlen < pqcrystals_kyber768_BYTES) {
            return 0;
        }
        
        /* 执行Kyber-768密钥封装 */
        pqcrystals_kyber768_ref_enc(out, secret, pubkey);
        
        *outlen = pqcrystals_kyber768_CIPHERTEXTBYTES;
        *secretlen = pqcrystals_kyber768_BYTES;
        ret = 1;
        break;

    case 1024:
        /* 验证输出缓冲区大小 */
        if (out == NULL || secret == NULL) {
            *outlen = pqcrystals_kyber1024_CIPHERTEXTBYTES;
            *secretlen = pqcrystals_kyber1024_BYTES;
            return 1;
        }
        
        if (*outlen < pqcrystals_kyber1024_CIPHERTEXTBYTES ||
            *secretlen < pqcrystals_kyber1024_BYTES) {
            return 0;
        }
        
        /* 执行Kyber-1024密钥封装 */
        pqcrystals_kyber1024_ref_enc(out, secret, pubkey);
        
        *outlen = pqcrystals_kyber1024_CIPHERTEXTBYTES;
        *secretlen = pqcrystals_kyber1024_BYTES;
        ret = 1;
        break;
        
    default:
        return 0;
    }

    return ret;
}

/* 密钥解封装 - 从密文恢复共享密钥 */
static int kyber_kem_decapsulate(void *ctx, unsigned char *secret, size_t *secretlen,
                           const unsigned char *in, size_t inlen)
{
    KYBER_KEM_CTX *kctx = (KYBER_KEM_CTX *)ctx;
    KYBER_KEY *key;
    unsigned char *privkey;
    int version;
    int ret = 0;
    
    if (kctx == NULL)
        return 0;

    key = kctx->pkey;
    if (key == NULL || key->secret_key == NULL)
        return 0;

    version = key->version;
    privkey = key->secret_key;
    
    /* 根据安全级别处理不同逻辑 */
    switch (version) {
    case 512:
        /* 检查输入参数 */
        if (in == NULL || inlen != pqcrystals_kyber512_CIPHERTEXTBYTES)
            return 0;
            
        /* 验证输出缓冲区 */
        if (secret == NULL) {
            *secretlen = pqcrystals_kyber512_BYTES;
            return 1;
        }
        
        if (*secretlen < pqcrystals_kyber512_BYTES)
            return 0;
            
        /* 执行Kyber-512密钥解封装 */
        pqcrystals_kyber512_ref_dec(secret, in, privkey);
        
        *secretlen = pqcrystals_kyber512_BYTES;
        ret = 1;
        break;

    case 768:
        /* 检查输入参数 */
        if (in == NULL || inlen != pqcrystals_kyber768_CIPHERTEXTBYTES)
            return 0;
            
        /* 验证输出缓冲区 */
        if (secret == NULL) {
            *secretlen = pqcrystals_kyber768_BYTES;
            return 1;
        }
        
        if (*secretlen < pqcrystals_kyber768_BYTES)
            return 0;
            
        /* 执行Kyber-768密钥解封装 */
        pqcrystals_kyber768_ref_dec(secret, in, privkey);
        
        *secretlen = pqcrystals_kyber768_BYTES;
        ret = 1;
        break;

    case 1024:
        /* 检查输入参数 */
        if (in == NULL || inlen != pqcrystals_kyber1024_CIPHERTEXTBYTES)
            return 0;
            
        /* 验证输出缓冲区 */
        if (secret == NULL) {
            *secretlen = pqcrystals_kyber1024_BYTES;
            return 1;
        }
        
        if (*secretlen < pqcrystals_kyber1024_BYTES)
            return 0;
            
        /* 执行Kyber-1024密钥解封装 */
        pqcrystals_kyber1024_ref_dec(secret, in, privkey);
        
        *secretlen = pqcrystals_kyber1024_BYTES;
        ret = 1;
        break;
        
    default:
        return 0;
    }

    return ret;
}

/* 获取参数定义 */
static const OSSL_PARAM *kyber_kem_gettable_ctx_params(void *provctx, void *ctx)
{
    static const OSSL_PARAM gettable_ctx_params[] = {
        OSSL_PARAM_END
    };
    return gettable_ctx_params;
}

/* 获取参数值 */
static int kyber_kem_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    if (ctx == NULL || params == NULL)
        return 0;
    return 1;
}

/* 可设置的参数定义 */
static const OSSL_PARAM *kyber_kem_settable_ctx_params(void *provctx, void *ctx)
{
    static const OSSL_PARAM settable_ctx_params[] = {
        OSSL_PARAM_END
    };
    return settable_ctx_params;
}

/* 设置参数值 */
static int kyber_kem_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    if (ctx == NULL || params == NULL)
        return 0;
    return 1;
}

/* Kyber-512 KEM函数分发表 */
const OSSL_DISPATCH kyber512_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))kyber_kem_newctx },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))kyber_kem_freectx },
    { OSSL_FUNC_KEM_DUPCTX, (void (*)(void))kyber_kem_dupctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))kyber_kem_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))kyber_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))kyber_kem_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))kyber_kem_decapsulate },
    { OSSL_FUNC_KEM_GET_CTX_PARAMS, (void (*)(void))kyber_kem_get_ctx_params },
    { OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS, (void (*)(void))kyber_kem_gettable_ctx_params },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS, (void (*)(void))kyber_kem_set_ctx_params },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, (void (*)(void))kyber_kem_settable_ctx_params },
    { 0, NULL }
};

/* Kyber-768 KEM函数分发表 */
const OSSL_DISPATCH kyber768_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))kyber_kem_newctx },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))kyber_kem_freectx },
    { OSSL_FUNC_KEM_DUPCTX, (void (*)(void))kyber_kem_dupctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))kyber_kem_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))kyber_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))kyber_kem_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))kyber_kem_decapsulate },
    { OSSL_FUNC_KEM_GET_CTX_PARAMS, (void (*)(void))kyber_kem_get_ctx_params },
    { OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS, (void (*)(void))kyber_kem_gettable_ctx_params },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS, (void (*)(void))kyber_kem_set_ctx_params },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, (void (*)(void))kyber_kem_settable_ctx_params },
    { 0, NULL }
};

/* Kyber-1024 KEM函数分发表 */
const OSSL_DISPATCH kyber1024_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))kyber_kem_newctx },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))kyber_kem_freectx },
    { OSSL_FUNC_KEM_DUPCTX, (void (*)(void))kyber_kem_dupctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))kyber_kem_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))kyber_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))kyber_kem_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))kyber_kem_decapsulate },
    { OSSL_FUNC_KEM_GET_CTX_PARAMS, (void (*)(void))kyber_kem_get_ctx_params },
    { OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS, (void (*)(void))kyber_kem_gettable_ctx_params },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS, (void (*)(void))kyber_kem_set_ctx_params },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, (void (*)(void))kyber_kem_settable_ctx_params },
    { 0, NULL }
};
