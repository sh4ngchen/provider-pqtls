#include <string.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_object.h>
#include <openssl/rand.h>
#include "../include/impl.h"
#include "../include/dilithium.h"

/* 上下文管理函数 */
static void *dilithium_newctx(void *provctx, int version, const char *propq)
{
    DILITHIUM_SIGN_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    
    if (ctx == NULL)
        return NULL;
    
    ctx->provctx = provctx;
    ctx->md = NULL;
    ctx->mdctx = NULL;
    ctx->tbs = NULL;
    ctx->sig = NULL;
    
    /* 设置属性查询字符串 */
    if (propq != NULL && (ctx->propq = OPENSSL_strdup(propq)) == NULL) {
        OPENSSL_free(ctx);
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    
    /* 设置默认消息摘要算法（可选，如果不需要哈希，设为NULL） */
    ctx->md = EVP_MD_fetch(PROV_CTX_get0_libctx(provctx), "SHA3-256", propq);
    if (ctx->md != NULL) {
        ctx->mdsize = EVP_MD_get_size(ctx->md);
        ctx->mdctx = EVP_MD_CTX_new();
        if (ctx->mdctx == NULL) {
            EVP_MD_free(ctx->md);
            OPENSSL_free(ctx->propq);
            OPENSSL_free(ctx);
            return NULL;
        }
    }
    
    return ctx;
}

/* 释放签名上下文 */
static void dilithium_freectx(void *vctx)
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;
    
    if (ctx == NULL)
        return;
    
    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);
    OPENSSL_free(ctx->propq);
    
    /* 释放密钥和缓冲区 */
    if (ctx->pkey != NULL) {
        OPENSSL_secure_clear_free(ctx->pkey->secret_key, ctx->pkey->secret_key_len);
        OPENSSL_free(ctx->pkey->public_key);
        OPENSSL_free(ctx->pkey);
    }
    
    OPENSSL_free(ctx->tbs);
    OPENSSL_free(ctx->sig);
    OPENSSL_free(ctx);
}

/* 复制签名上下文 */
static void *dilithium_dupctx(void *vctx)
{
    DILITHIUM_SIGN_CTX *src = (DILITHIUM_SIGN_CTX *)vctx;
    DILITHIUM_SIGN_CTX *dst = NULL;
    
    if (src == NULL)
        return NULL;
    
    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL)
        return NULL;
    
    dst->provctx = src->provctx;
    
    /* 复制属性查询字符串 */
    if (src->propq != NULL && (dst->propq = OPENSSL_strdup(src->propq)) == NULL)
        goto err;
    
    if (src->md != NULL) {
        dst->md = src->md;
        EVP_MD_up_ref(dst->md);
        dst->mdsize = src->mdsize;
        
        dst->mdctx = EVP_MD_CTX_new();
        if (dst->mdctx == NULL)
            goto err;
        
        if (!EVP_MD_CTX_copy_ex(dst->mdctx, src->mdctx))
            goto err;
    }
    
    /* 复制密钥 */
    if (src->pkey != NULL) {
        dst->pkey = OPENSSL_zalloc(sizeof(*dst->pkey));
        if (dst->pkey == NULL)
            goto err;
        
        *dst->pkey = *src->pkey;
        
        if (src->pkey->secret_key != NULL) {
            dst->pkey->secret_key = OPENSSL_secure_malloc(src->pkey->secret_key_len);
            if (dst->pkey->secret_key == NULL)
                goto err;
            memcpy(dst->pkey->secret_key, src->pkey->secret_key, src->pkey->secret_key_len);
        }
        
        if (src->pkey->public_key != NULL) {
            dst->pkey->public_key = OPENSSL_malloc(src->pkey->public_key_len);
            if (dst->pkey->public_key == NULL)
                goto err;
            memcpy(dst->pkey->public_key, src->pkey->public_key, src->pkey->public_key_len);
        }
    }
    
    /* 复制缓冲区 */
    if (src->tbs != NULL && src->tbslen > 0) {
        dst->tbs = OPENSSL_malloc(src->tbslen);
        if (dst->tbs == NULL)
            goto err;
        memcpy(dst->tbs, src->tbs, src->tbslen);
        dst->tbslen = src->tbslen;
    }
    
    if (src->sig != NULL && src->siglen > 0) {
        dst->sig = OPENSSL_malloc(src->siglen);
        if (dst->sig == NULL)
            goto err;
        memcpy(dst->sig, src->sig, src->siglen);
        dst->siglen = src->siglen;
    }
    
    return dst;

err:
    dilithium_freectx(dst);
    return NULL;
}

/* 获取可用参数 */
static const OSSL_PARAM *dilithium_gettable_ctx_params(void *vctx, void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
        OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_END
    };
    
    return known_gettable_ctx_params;
}

/* 获取参数 */
static int dilithium_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;
    OSSL_PARAM *p;
    
    if (ctx == NULL)
        return 0;
    
    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->mdsize))
        return 0;
    
    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && ctx->md != NULL &&
        !OSSL_PARAM_set_utf8_string(p, EVP_MD_get0_name(ctx->md)))
        return 0;
    
    return 1;
}

/* 获取可设置参数 */
static const OSSL_PARAM *dilithium_settable_ctx_params(void *vctx, void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_END
    };
    
    return known_settable_ctx_params;
}

/* 设置参数 */
static int dilithium_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;
    const OSSL_PARAM *p;
    
    if (ctx == NULL)
        return 0;
    
    /* 处理摘要算法参数 */
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        
        /* 释放旧的摘要算法 */
        EVP_MD_CTX_free(ctx->mdctx);
        EVP_MD_free(ctx->md);
        
        /* 如果设置为NULL或空字符串，则不使用摘要 */
        if (p->data == NULL || ((char *)p->data)[0] == '\0') {
            ctx->md = NULL;
            ctx->mdctx = NULL;
            ctx->mdsize = 0;
            return 1;
        }
        
        /* 获取新的摘要算法 */
        ctx->md = EVP_MD_fetch(PROV_CTX_get0_libctx(ctx->provctx),
                              p->data, ctx->propq);
        if (ctx->md == NULL)
            return 0;
        
        ctx->mdsize = EVP_MD_get_size(ctx->md);
        
        /* 创建新的摘要上下文 */
        ctx->mdctx = EVP_MD_CTX_new();
        if (ctx->mdctx == NULL) {
            EVP_MD_free(ctx->md);
            ctx->md = NULL;
            return 0;
        }
    }
    
    return 1;
}

/* 获取可获取密钥参数 */
static const OSSL_PARAM *dilithium_gettable_ctx_md_params(void *vctx)
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;
    
    if (ctx != NULL && ctx->md != NULL)
        return EVP_MD_gettable_ctx_params(ctx->md);
    
    return NULL;
}

/* 获取摘要参数 */
static int dilithium_get_ctx_md_params(void *vctx, OSSL_PARAM params[])
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;
    
    if (ctx != NULL && ctx->md != NULL)
        return EVP_MD_CTX_get_params(ctx->mdctx, params);
    
    return 0;
}

/* 获取可设置摘要参数 */
static const OSSL_PARAM *dilithium_settable_ctx_md_params(void *vctx)
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;
    
    if (ctx != NULL && ctx->md != NULL)
        return EVP_MD_settable_ctx_params(ctx->md);
    
    return NULL;
}

/* 设置摘要参数 */
static int dilithium_set_ctx_md_params(void *vctx, const OSSL_PARAM params[])
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;
    
    if (ctx != NULL && ctx->md != NULL)
        return EVP_MD_CTX_set_params(ctx->mdctx, params);
    
    return 0;
}

/* 检查签名算法参数 */
static int dilithium_signature_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;
    DILITHIUM_KEY *key = vkey;
    
    if (!dilithium_set_ctx_params(ctx, params))
        return 0;
    
    if (key == NULL)
        return 1;
    
    /* 保存密钥 */
    if (ctx->pkey != NULL) {
        OPENSSL_secure_clear_free(ctx->pkey->secret_key, ctx->pkey->secret_key_len);
        OPENSSL_free(ctx->pkey->public_key);
        OPENSSL_free(ctx->pkey);
    }
    
    ctx->pkey = OPENSSL_zalloc(sizeof(*ctx->pkey));
    if (ctx->pkey == NULL)
        return 0;
    
    ctx->pkey->version = key->version;
    ctx->pkey->public_key_len = key->public_key_len;
    ctx->pkey->secret_key_len = key->secret_key_len;
    ctx->pkey->sig_len = key->sig_len;
    
    if (key->public_key != NULL && key->has_public) {
        ctx->pkey->public_key = OPENSSL_malloc(key->public_key_len);
        if (ctx->pkey->public_key == NULL)
            return 0;
        memcpy(ctx->pkey->public_key, key->public_key, key->public_key_len);
        ctx->pkey->has_public = 1;
    }
    
    if (key->secret_key != NULL && key->has_private) {
        ctx->pkey->secret_key = OPENSSL_secure_malloc(key->secret_key_len);
        if (ctx->pkey->secret_key == NULL)
            return 0;
        memcpy(ctx->pkey->secret_key, key->secret_key, key->secret_key_len);
        ctx->pkey->has_private = 1;
    }
    
    return 1;
}

/* 签名生成 */
static int dilithium_sign(void *vctx, unsigned char *sig, size_t *siglen,
                         size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;
    unsigned char *data_to_sign = NULL;
    size_t data_len = 0;
    int ret = 0;
    
    if (ctx == NULL || ctx->pkey == NULL || !ctx->pkey->has_private) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }

    /* 分配足够的签名空间 */
    if (sig == NULL) {
        *siglen = ctx->pkey->sig_len;
        return 1;
    }
    
    if (sigsize < ctx->pkey->sig_len) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    
    /* 决定要签名的数据，根据是否使用摘要 */
    if (ctx->md != NULL) {
        unsigned char mdbuf[EVP_MAX_MD_SIZE];
        unsigned int mdlen = 0;
        
        if (!EVP_DigestFinal_ex(ctx->mdctx, mdbuf, &mdlen))
            return 0;
        
        data_to_sign = mdbuf;
        data_len = mdlen;
    } else {
        data_to_sign = (unsigned char *)tbs;
        data_len = tbslen;
    }
    
    /* 根据版本执行签名操作 */
    switch (ctx->pkey->version) {
    case 2:
        ret = pqcrystals_dilithium2_ref_signature(sig, siglen, data_to_sign, data_len, 
                                                  NULL, 0, ctx->pkey->secret_key);
        break;
    case 3:
        ret = pqcrystals_dilithium3_ref_signature(sig, siglen, data_to_sign, data_len, 
                                                  NULL, 0, ctx->pkey->secret_key);
        break;
    case 5:
        ret = pqcrystals_dilithium5_ref_signature(sig, siglen, data_to_sign, data_len, 
                                                  NULL, 0, ctx->pkey->secret_key);
        break;
    default:
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }
    
    if (ret != 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SIGN);
        return 0;
    }
    
    return 1;
}

/* 签名最终处理 */
static int dilithium_signature_final(void *vctx, unsigned char *sig, size_t *siglen, 
                                    size_t sigsize)
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;
    unsigned char *data_to_sign = NULL;
    size_t data_len = 0;
    int ret = 0;
    
    if (ctx == NULL || ctx->pkey == NULL || !ctx->pkey->has_private) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }
    
    /* 分配足够的签名空间 */
    if (sig == NULL) {
        *siglen = ctx->pkey->sig_len;
        return 1;
    }
    
    if (sigsize < ctx->pkey->sig_len) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    
    /* 决定要签名的数据，根据是否使用摘要 */
    if (ctx->md != NULL) {
        unsigned char mdbuf[EVP_MAX_MD_SIZE];
        unsigned int mdlen = 0;
        
        if (!EVP_DigestFinal_ex(ctx->mdctx, mdbuf, &mdlen))
            return 0;
        
        data_to_sign = mdbuf;
        data_len = mdlen;
    } else {
        if (ctx->tbs == NULL) {
            return 0;
        }
        
        data_to_sign = ctx->tbs;
        data_len = ctx->tbslen;
    }
    
    /* 根据版本执行签名操作 */
    switch (ctx->pkey->version) {
    case 2:
        ret = pqcrystals_dilithium2_ref_signature(sig, siglen, data_to_sign, data_len, 
                                                  NULL, 0, ctx->pkey->secret_key);
        break;
    case 3:
        ret = pqcrystals_dilithium3_ref_signature(sig, siglen, data_to_sign, data_len, 
                                                  NULL, 0, ctx->pkey->secret_key);
        break;
    case 5:
        ret = pqcrystals_dilithium5_ref_signature(sig, siglen, data_to_sign, data_len, 
                                                  NULL, 0, ctx->pkey->secret_key);
        break;
    default:
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }
    
    if (ret != 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SIGN);
        return 0;
    }
    
    return 1;
}

/* 签名验证 */
static int dilithium_verify(void *vctx, const unsigned char *sig, size_t siglen,
                           const unsigned char *tbs, size_t tbslen)
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;
    unsigned char *data_to_verify = NULL;
    size_t data_len = 0;
    int ret = 0;
    
    if (ctx == NULL || ctx->pkey == NULL || !ctx->pkey->has_public) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }
    
    /* 决定要验证的数据，根据是否使用摘要 */
    if (ctx->md != NULL) {
        unsigned char mdbuf[EVP_MAX_MD_SIZE];
        unsigned int mdlen = 0;
        
        if (!EVP_DigestFinal_ex(ctx->mdctx, mdbuf, &mdlen))
            return 0;
        
        data_to_verify = mdbuf;
        data_len = mdlen;
    } else {
        data_to_verify = (unsigned char *)tbs;
        data_len = tbslen;
    }
    
    /* 根据版本执行验证操作 */
    switch (ctx->pkey->version) {
    case 2:
        ret = pqcrystals_dilithium2_ref_verify(sig, siglen, data_to_verify, data_len, 
                                               NULL, 0, ctx->pkey->public_key);
        break;
    case 3:
        ret = pqcrystals_dilithium3_ref_verify(sig, siglen, data_to_verify, data_len, 
                                               NULL, 0, ctx->pkey->public_key);
        break;
    case 5:
        ret = pqcrystals_dilithium5_ref_verify(sig, siglen, data_to_verify, data_len, 
                                               NULL, 0, ctx->pkey->public_key);
        break;
    default:
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }
    
    if (ret != 0) {
        return 0;
    }
    
    return 1;
}

/* 签名验证最终处理 */
static int dilithium_verify_final(void *vctx, const unsigned char *sig, size_t siglen)
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;
    unsigned char *data_to_verify = NULL;
    size_t data_len = 0;
    int ret = 0;
    
    if (ctx == NULL || ctx->pkey == NULL || !ctx->pkey->has_public) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }
    
    /* 决定要验证的数据，根据是否使用摘要 */
    if (ctx->md != NULL) {
        unsigned char mdbuf[EVP_MAX_MD_SIZE];
        unsigned int mdlen = 0;
        
        if (!EVP_DigestFinal_ex(ctx->mdctx, mdbuf, &mdlen))
            return 0;
        
        data_to_verify = mdbuf;
        data_len = mdlen;
    } else {
        if (ctx->tbs == NULL) {
            return 0;
        }
        
        data_to_verify = ctx->tbs;
        data_len = ctx->tbslen;
    }
    
    /* 根据版本执行验证操作 */
    switch (ctx->pkey->version) {
    case 2:
        ret = pqcrystals_dilithium2_ref_verify(sig, siglen, data_to_verify, data_len, 
                                               NULL, 0, ctx->pkey->public_key);
        break;
    case 3:
        ret = pqcrystals_dilithium3_ref_verify(sig, siglen, data_to_verify, data_len, 
                                               NULL, 0, ctx->pkey->public_key);
        break;
    case 5:
        ret = pqcrystals_dilithium5_ref_verify(sig, siglen, data_to_verify, data_len, 
                                               NULL, 0, ctx->pkey->public_key);
        break;
    default:
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }
    
    if (ret != 0) {
        return 0;
    }
    
    return 1;
}

/* 摘要签名初始化函数 */
static int dilithium_digest_sign_init(void *vctx, const char *mdname,
                                    void *vkey, const OSSL_PARAM params[])
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;
    OSSL_PARAM digest_params[2], *p = digest_params;
    int ret;

    if (ctx == NULL || mdname == NULL)
        return 0;

    /* 首先初始化签名上下文 */
    if (!dilithium_signature_init(ctx, vkey, params))
        return 0;

    /* 设置摘要算法 */
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, 
                                           (char *)mdname, 0);
    *p = OSSL_PARAM_construct_end();

    /* 应用摘要算法参数 */
    ret = dilithium_set_ctx_params(ctx, digest_params);
    if (ret && ctx->md != NULL)
        ret = EVP_DigestInit_ex(ctx->mdctx, ctx->md, NULL);

    return ret;
}

/* 摘要验证初始化函数 */
static int dilithium_digest_verify_init(void *vctx, const char *mdname,
                                      void *vkey, const OSSL_PARAM params[])
{
    /* 验证初始化与签名初始化使用相同的逻辑 */
    return dilithium_digest_sign_init(vctx, mdname, vkey, params);
}

/* 摘要签名/验证数据更新函数 */
static int dilithium_digest_signverify_update(void *vctx, const unsigned char *data,
                                            size_t datalen)
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;

    if (ctx == NULL || ctx->md == NULL)
        return 0;

    /* 使用摘要上下文更新数据 */
    return EVP_DigestUpdate(ctx->mdctx, data, datalen);
}

/* 摘要签名最终处理函数 */
static int dilithium_digest_sign_final(void *vctx, unsigned char *sig, size_t *siglen, 
                                     size_t sigsize)
{
    /* 此处直接使用已实现的签名最终处理函数 */
    return dilithium_signature_final(vctx, sig, siglen, sigsize);
}

/* 摘要验证最终处理函数 */
static int dilithium_digest_verify_final(void *vctx, const unsigned char *sig, 
                                       size_t siglen)
{
    /* 此处直接使用已实现的验证最终处理函数 */
    return dilithium_verify_final(vctx, sig, siglen);
}

/* 为各个Dilithium版本创建上下文 */
static OSSL_FUNC_signature_newctx_fn dilithium2_newctx;
static void *dilithium2_newctx(void *provctx, const char *propq)
{
    return dilithium_newctx(provctx, 2, propq);
}

static OSSL_FUNC_signature_newctx_fn dilithium3_newctx;
static void *dilithium3_newctx(void *provctx, const char *propq)
{
    return dilithium_newctx(provctx, 3, propq);
}

static OSSL_FUNC_signature_newctx_fn dilithium5_newctx;
static void *dilithium5_newctx(void *provctx, const char *propq)
{
    return dilithium_newctx(provctx, 5, propq);
}

/* 分发表定义 - Dilithium2 */
const OSSL_DISPATCH dilithium2_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))dilithium2_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))dilithium_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))dilithium_dupctx },
    /* 基本签名操作 */
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))dilithium_signature_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))dilithium_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))dilithium_signature_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))dilithium_verify },
    /* 一次性摘要+签名操作 */
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))dilithium_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))dilithium_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))dilithium_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))dilithium_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))dilithium_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))dilithium_digest_verify_final },
    /* 参数相关操作 */
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))dilithium_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))dilithium_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))dilithium_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))dilithium_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, (void (*)(void))dilithium_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, (void (*)(void))dilithium_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, (void (*)(void))dilithium_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, (void (*)(void))dilithium_settable_ctx_md_params },
    { 0, NULL }
};

/* 分发表定义 - Dilithium3 */
const OSSL_DISPATCH dilithium3_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))dilithium3_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))dilithium_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))dilithium_dupctx },
    /* 基本签名操作 */
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))dilithium_signature_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))dilithium_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))dilithium_signature_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))dilithium_verify },
    /* 一次性摘要+签名操作 */
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))dilithium_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))dilithium_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))dilithium_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))dilithium_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))dilithium_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))dilithium_digest_verify_final },
    /* 参数相关操作 */
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))dilithium_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))dilithium_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))dilithium_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))dilithium_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, (void (*)(void))dilithium_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, (void (*)(void))dilithium_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, (void (*)(void))dilithium_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, (void (*)(void))dilithium_settable_ctx_md_params },
    { 0, NULL }
};

/* 分发表定义 - Dilithium5 */
const OSSL_DISPATCH dilithium5_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))dilithium5_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))dilithium_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))dilithium_dupctx },
    /* 基本签名操作 */
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))dilithium_signature_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))dilithium_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))dilithium_signature_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))dilithium_verify },
    /* 一次性摘要+签名操作 */
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))dilithium_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))dilithium_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))dilithium_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))dilithium_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))dilithium_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))dilithium_digest_verify_final },
    /* 参数相关操作 */
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))dilithium_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))dilithium_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))dilithium_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))dilithium_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, (void (*)(void))dilithium_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, (void (*)(void))dilithium_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, (void (*)(void))dilithium_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, (void (*)(void))dilithium_settable_ctx_md_params },
    { 0, NULL }
};
