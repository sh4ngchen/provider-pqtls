#include <string.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_object.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include "../include/impl.h"
#include "../include/dilithium.h"

static int get_aid(unsigned char **oidbuf, const char *tls_name) {
    X509_ALGOR *algor = X509_ALGOR_new();
    int aidlen = 0;

    X509_ALGOR_set0(algor, OBJ_txt2obj(tls_name, 0), V_ASN1_UNDEF, NULL);

    aidlen = i2d_X509_ALGOR(algor, oidbuf);
    X509_ALGOR_free(algor);
    return (aidlen);
}

/* 上下文管理函数 */
static void *dilithium_newctx(void *provctx, int version, const char *propq)
{
    DILITHIUM_SIGN_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx == NULL)
        return NULL;

    ctx->provctx = provctx;

    /* 设置属性查询字符串 */
    if (propq != NULL && (ctx->propq = OPENSSL_strdup(propq)) == NULL) {
        OPENSSL_free(ctx);
        ctx = NULL;
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
    }
    return ctx;
}

static int dilithium_sig_setup_md(void *vctx, const char *mdname, const char *mdprops)
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;
    OSSL_LIB_CTX *libctx = PROV_CTX_get0_libctx(ctx->provctx);

    if (mdprops == NULL)
        mdprops = ctx->propq;

    if (mdname != NULL) {
        EVP_MD *md = EVP_MD_fetch(libctx, mdname, mdprops);

        if ((md == NULL) || (EVP_MD_nid(md) == NID_undef)) {
            ERR_raise_data(ERR_LIB_USER, PROV_R_INVALID_DIGEST,
                           "%s could not be fetched", mdname);
            EVP_MD_free(md);
            return 0;
        }

        /* 释放旧的摘要和上下文 */
        EVP_MD_CTX_free(ctx->mdctx);
        ctx->mdctx = NULL;
        EVP_MD_free(ctx->md);
        ctx->md = NULL;

        if (ctx->aid)
            OPENSSL_free(ctx->aid);
        ctx->aid = NULL;
        ctx->aidlen = get_aid(&(ctx->aid), ctx->pkey->tls_name);
    }
    return 1;
}

/* 释放签名上下文 */
static void dilithium_freectx(void *vctx)
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;

    if (ctx == NULL)
        return;

    /* 释放消息摘要相关资源 */
    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);

    /* 释放属性查询字符串 */
    OPENSSL_free(ctx->propq);

    /* 释放密钥和缓冲区 */
    if (ctx->pkey != NULL)
    {
        if (ctx->pkey->secret_key != NULL)
            OPENSSL_secure_clear_free(ctx->pkey->secret_key, ctx->pkey->secret_key_len);
        OPENSSL_free(ctx->pkey->public_key);
        OPENSSL_free(ctx->pkey);
    }

    /* 释放缓冲区 */
    OPENSSL_free(ctx->tbs);
    OPENSSL_free(ctx->sig);
    OPENSSL_free(ctx->aid);

    /* 释放上下文 */
    OPENSSL_free(ctx);
}

/* 复制签名上下文 */
static void *dilithium_dupctx(void *vctx)
{
    DILITHIUM_SIGN_CTX *src = (DILITHIUM_SIGN_CTX *)vctx;
    DILITHIUM_SIGN_CTX *dst;

    if (src == NULL)
        return NULL;

    /* 分配新的上下文 */
    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL)
    {
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /* 复制基本信息 */
    dst->provctx = src->provctx;
    dst->flag_allow_md = src->flag_allow_md;
    dst->mdsize = src->mdsize;
    dst->tbslen = 0;
    dst->siglen = 0;

    /* 复制属性查询字符串 */
    if (src->propq != NULL)
    {
        dst->propq = OPENSSL_strdup(src->propq);
        if (dst->propq == NULL)
            goto err;
    }

    /* 复制消息摘要名称 */
    if (src->mdname[0] != '\0')
        OPENSSL_strlcpy(dst->mdname, src->mdname, sizeof(dst->mdname));

    /* 复制消息摘要 */
    if (src->md != NULL)
    {
        dst->md = src->md;
        EVP_MD_up_ref(dst->md);

        /* 创建并复制消息摘要上下文 */
        if (src->mdctx != NULL)
        {
            dst->mdctx = EVP_MD_CTX_new();
            if (dst->mdctx == NULL || !EVP_MD_CTX_copy_ex(dst->mdctx, src->mdctx))
                goto err;
        }
    }

    /* 复制密钥 */
    if (src->pkey != NULL)
    {
        dst->pkey = OPENSSL_zalloc(sizeof(*dst->pkey));
        if (dst->pkey == NULL)
            goto err;

        *dst->pkey = *src->pkey;

        /* 复制私钥 */
        if (src->pkey->secret_key != NULL && src->pkey->has_private)
        {
            dst->pkey->secret_key = OPENSSL_secure_malloc(src->pkey->secret_key_len);
            if (dst->pkey->secret_key == NULL)
                goto err;
            memcpy(dst->pkey->secret_key, src->pkey->secret_key, src->pkey->secret_key_len);
        }

        /* 复制公钥 */
        if (src->pkey->public_key != NULL && src->pkey->has_public)
        {
            dst->pkey->public_key = OPENSSL_malloc(src->pkey->public_key_len);
            if (dst->pkey->public_key == NULL)
                goto err;
            memcpy(dst->pkey->public_key, src->pkey->public_key, src->pkey->public_key_len);
        }
    }

    /* 复制缓冲区 */
    if (src->tbs != NULL && src->tbslen > 0)
    {
        dst->tbs = OPENSSL_malloc(src->tbslen);
        if (dst->tbs == NULL)
            goto err;
        memcpy(dst->tbs, src->tbs, src->tbslen);
        dst->tbslen = src->tbslen;
    }

    if (src->sig != NULL && src->siglen > 0)
    {
        dst->sig = OPENSSL_malloc(src->siglen);
        if (dst->sig == NULL)
            goto err;
        memcpy(dst->sig, src->sig, src->siglen);
        dst->siglen = src->siglen;
    }

    /* 复制算法ID */
    if (src->aid != NULL && src->aidlen > 0)
    {
        dst->aid = OPENSSL_malloc(src->aidlen);
        if (dst->aid == NULL)
            goto err;
        memcpy(dst->aid, src->aid, src->aidlen);
        dst->aidlen = src->aidlen;
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
        OSSL_PARAM_END};

    return known_gettable_ctx_params;
}

/* 获取参数 */
static int dilithium_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    /* 获取算法ID */
    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL)
    {
        /* 确保算法ID已生成 */
        if (ctx->aid == NULL && ctx->pkey != NULL)
        {
            const char *tls_name;
            switch (ctx->pkey->version)
            {
            case 2:
                tls_name = "dilithium2";
                break;
            case 3:
                tls_name = "dilithium3";
                break;
            case 5:
                tls_name = "dilithium5";
                break;
            default:
                return 0;
            }
            ctx->aidlen = get_aid(&(ctx->aid), tls_name);
            if (ctx->aidlen <= 0)
                return 0;
        }

        if (ctx->aid != NULL &&
            !OSSL_PARAM_set_octet_string(p, ctx->aid, ctx->aidlen))
            return 0;
    }

    /* 获取摘要大小 */
    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->mdsize))
        return 0;

    /* 获取摘要名称 */
    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && ctx->md != NULL &&
        !OSSL_PARAM_set_utf8_string(p, ctx->mdname))
        return 0;

    return 1;
}

/* 获取可设置参数 */
static const OSSL_PARAM *dilithium_settable_ctx_params(void *vctx, void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END};

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
    if (p != NULL)
    {
        /* 只有在允许的情况下才更改摘要算法 */
        if (!ctx->flag_allow_md)
        {
            return 0;
        }

        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;

        char mdname[OSSL_MAX_NAME_SIZE] = "";
        char mdprops[OSSL_MAX_PROPQUERY_SIZE] = "";
        char *pmdname = mdname;
        char *pmdprops = mdprops;

        if (!OSSL_PARAM_get_utf8_string(p, &pmdname, sizeof(mdname)))
            return 0;

        /* 获取属性查询字符串 */
        const OSSL_PARAM *propsp =
            OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PROPERTIES);
        if (propsp != NULL &&
            !OSSL_PARAM_get_utf8_string(propsp, &pmdprops, sizeof(mdprops)))
            return 0;

        /* 设置新的摘要算法 */
        return dilithium_sig_setup_md(ctx, mdname, mdprops);
    }

    return 1;
}

/* 获取可获取摘要参数 */
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

    if (ctx != NULL && ctx->mdctx != NULL)
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

    if (ctx != NULL && ctx->mdctx != NULL)
        return EVP_MD_CTX_set_params(ctx->mdctx, params);

    return 0;
}

/* 签名初始化函数 */
static int dilithium_signverify_init(void *vctx, void *vkey, int operation)
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;
    DILITHIUM_KEY *key = vkey;

    if (ctx == NULL || key == NULL)
        return 0;

    ctx->pkey = key;
    ctx->pkey->references++;
    ctx->operation = operation;
    ctx->flag_allow_md = 1;

    /* 检查密钥类型是否符合操作类型 */
    if ((operation == EVP_PKEY_OP_SIGN && !key->has_private) ||
        (operation == EVP_PKEY_OP_VERIFY && !key->has_public)) {
        ERR_raise(ERR_LIB_USER, PROV_R_INVALID_KEY);
        return 0;
    }
    return 1;
}

/* 签名初始化 */
static int dilithium_signature_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    if (!dilithium_signverify_init(vctx, vkey, EVP_PKEY_OP_SIGN))
        return 0;

    return dilithium_set_ctx_params(vctx, params);
}

/* 验证初始化 */
static int dilithium_verify_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    if (!dilithium_signverify_init(vctx, vkey, EVP_PKEY_OP_VERIFY))
        return 0;

    return dilithium_set_ctx_params(vctx, params);
}

/* 签名生成 */
static int dilithium_sign(void *vctx, unsigned char *sig, size_t *siglen,
                          size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;
    int ret = 0;

    if (ctx == NULL || ctx->pkey == NULL || !ctx->pkey->has_private)
    {
        ERR_raise(ERR_LIB_USER, PROV_R_INVALID_KEY);
        return 0;
    }

    /* 分配足够的签名空间 */
    if (sig == NULL)
    {
        *siglen = ctx->pkey->sig_len;
        return 1;
    }

    if (sigsize < ctx->pkey->sig_len)
    {
        ERR_raise(ERR_LIB_USER, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    /* 根据版本执行签名操作 */
    switch (ctx->pkey->version)
    {
    case 2:
        ret = pqcrystals_dilithium2_ref_signature(sig, siglen, tbs, tbslen,
                                                  NULL, 0, ctx->pkey->secret_key);
        break;
    case 3:
        ret = pqcrystals_dilithium3_ref_signature(sig, siglen, tbs, tbslen,
                                                  NULL, 0, ctx->pkey->secret_key);
        break;
    case 5:
        ret = pqcrystals_dilithium5_ref_signature(sig, siglen, tbs, tbslen,
                                                  NULL, 0, ctx->pkey->secret_key);
        break;
    default:
        ERR_raise(ERR_LIB_USER, PROV_R_INVALID_KEY);
        return 0;
    }

    if (ret != 0)
    {
        return 0;
    }

    return 1;
}

/* 摘要签名更新 */
static int dilithium_digest_signverify_update(void *vctx, const unsigned char *data, size_t datalen)
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;

    if (ctx == NULL)
        return 0;

    /* 不允许更改摘要算法 */
    ctx->flag_allow_md = 0;

    if (ctx->mdctx)
        return EVP_DigestUpdate(ctx->mdctx, data, datalen);
    else {
        if (ctx->tbs) {
            unsigned char *newdata = OPENSSL_realloc(ctx->tbs, ctx->tbslen + datalen);
            if (newdata == NULL)
                return 0;
            memcpy(newdata + ctx->tbslen, data, datalen);
            ctx->tbs = newdata;
            ctx->tbslen += datalen;
        } else {
            ctx->tbs = OPENSSL_malloc(datalen);
            if (ctx->tbs == NULL)
                return 0;
            ctx->tbslen = datalen;
            memcpy(ctx->tbs, data, datalen);
        }
    }
    return 1;
}

/* 摘要签名最终处理 */
static int dilithium_digest_sign_final(void *vctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (ctx == NULL)
        return 0;

    if (sig != NULL)
    {
        if (ctx->mdctx != NULL)
            if (!EVP_DigestFinal_ex(ctx->mdctx, digest, &dlen))
                return 0;
    }

    ctx->flag_allow_md = 1;

    if (ctx->mdctx != NULL)
        return dilithium_sign(vctx, sig, siglen, sigsize, digest, (size_t)dlen);
    else
        return dilithium_sign(vctx, sig, siglen, sigsize, ctx->tbs, ctx->tbslen);
}

/* 签名验证 */
static int dilithium_verify(void *vctx, const unsigned char *sig, size_t siglen,
                            const unsigned char *tbs, size_t tbslen)
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;
    int ret = 0;

    if (ctx == NULL || ctx->pkey == NULL || !ctx->pkey->has_public)
    {
        ERR_raise(ERR_LIB_USER, PROV_R_INVALID_KEY);
        return 0;
    }

    switch (ctx->pkey->version)
    {
    case 2:
        ret = pqcrystals_dilithium2_ref_verify(sig, siglen, tbs, tbslen,
                                               NULL, 0, ctx->pkey->public_key);
        break;
    case 3:
        ret = pqcrystals_dilithium3_ref_verify(sig, siglen, tbs, tbslen,
                                               NULL, 0, ctx->pkey->public_key);
        break;
    case 5:
        ret = pqcrystals_dilithium5_ref_verify(sig, siglen, tbs, tbslen,
                                               NULL, 0, ctx->pkey->public_key);
        break;
    default:
        ERR_raise(ERR_LIB_USER, PROV_R_INVALID_KEY);
        return 0;
    }

    /* 允许更改摘要算法 */
    ctx->flag_allow_md = 1;

    if (ret != 0)
    {
        return 0;
    }

    return 1;
}

/* 摘要验证最终处理 */
static int dilithium_digest_verify_final(void *vctx, const unsigned char *sig, size_t siglen)
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (ctx == NULL)
        return 0;

    /* 如果已经有消息摘要上下文，则调用普通的验证函数 */
    if (ctx->mdctx) {
        if (!EVP_DigestFinal_ex(ctx->mdctx, digest, &dlen))
            return 0;

        ctx->flag_allow_md = 1;

        return dilithium_verify(vctx, sig, siglen, digest, (size_t)dlen);
    }
    else
        return dilithium_verify(vctx, sig, siglen, ctx->tbs, ctx->tbslen);

    return 0;
}

/* 摘要签名初始化 */
static int dilithium_digest_sign_init(void *vctx, const char *mdname,
                                      void *vkey, const OSSL_PARAM params[])
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;

    /* 初始化为签名操作 */
    if (!dilithium_signverify_init(vctx, vkey, EVP_PKEY_OP_SIGN))
        return 0;

    /* 设置参数 */
    if (!dilithium_set_ctx_params(vctx, params))
        return 0;

    /* 设置摘要算法 */
    if (!dilithium_sig_setup_md(vctx, mdname, NULL))
        return 0;

    /* 创建并初始化摘要上下文 */
    if (mdname != NULL && ctx->md != NULL)
    {
        if (ctx->mdctx == NULL)
        {
            ctx->mdctx = EVP_MD_CTX_new();
            if (ctx->mdctx == NULL)
            {
                ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
                return 0;
            }
        }

        if (!EVP_DigestInit_ex(ctx->mdctx, ctx->md, NULL))
        {
            return 0;
        }
    }

    return 1;
}

/* 摘要验证初始化 */
static int dilithium_digest_verify_init(void *vctx, const char *mdname,
                                        void *vkey, const OSSL_PARAM params[])
{
    DILITHIUM_SIGN_CTX *ctx = (DILITHIUM_SIGN_CTX *)vctx;

    /* 初始化为验证操作 */
    if (!dilithium_signverify_init(vctx, vkey, EVP_PKEY_OP_VERIFY))
        return 0;

    /* 设置参数 */
    if (!dilithium_set_ctx_params(vctx, params))
        return 0;

    /* 设置摘要算法 */
    if (!dilithium_sig_setup_md(vctx, mdname, NULL))
        return 0;

    /* 创建并初始化摘要上下文 */
    if (mdname != NULL && ctx->md != NULL)
    {
        if (ctx->mdctx == NULL)
        {
            ctx->mdctx = EVP_MD_CTX_new();
            if (ctx->mdctx == NULL)
            {
                ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
                return 0;
            }
        }

        if (!EVP_DigestInit_ex(ctx->mdctx, ctx->md, NULL))
        {
            return 0;
        }
    }

    return 1;
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
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))dilithium2_newctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))dilithium_freectx},
    {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))dilithium_dupctx},
    /* 基本签名操作 */
    {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))dilithium_signature_init},
    {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))dilithium_sign},
    {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))dilithium_verify_init},
    {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))dilithium_verify},
    /* 摘要签名操作 */
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))dilithium_digest_sign_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))dilithium_digest_signverify_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))dilithium_digest_sign_final},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))dilithium_digest_verify_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))dilithium_digest_signverify_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))dilithium_digest_verify_final},
    /* 参数相关操作 */
    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))dilithium_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))dilithium_gettable_ctx_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))dilithium_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))dilithium_settable_ctx_params},
    {OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, (void (*)(void))dilithium_get_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, (void (*)(void))dilithium_gettable_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, (void (*)(void))dilithium_set_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, (void (*)(void))dilithium_settable_ctx_md_params},
    {0, NULL}};

/* 分发表定义 - Dilithium3 */
const OSSL_DISPATCH dilithium3_signature_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))dilithium3_newctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))dilithium_freectx},
    {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))dilithium_dupctx},
    /* 基本签名操作 */
    {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))dilithium_signature_init},
    {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))dilithium_sign},
    {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))dilithium_verify_init},
    {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))dilithium_verify},
    /* 摘要签名操作 */
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))dilithium_digest_sign_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))dilithium_digest_signverify_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))dilithium_digest_sign_final},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))dilithium_digest_verify_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))dilithium_digest_signverify_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))dilithium_digest_verify_final},
    /* 参数相关操作 */
    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))dilithium_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))dilithium_gettable_ctx_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))dilithium_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))dilithium_settable_ctx_params},
    {OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, (void (*)(void))dilithium_get_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, (void (*)(void))dilithium_gettable_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, (void (*)(void))dilithium_set_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, (void (*)(void))dilithium_settable_ctx_md_params},
    {0, NULL}};

/* 分发表定义 - Dilithium5 */
const OSSL_DISPATCH dilithium5_signature_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))dilithium5_newctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))dilithium_freectx},
    {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))dilithium_dupctx},
    /* 基本签名操作 */
    {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))dilithium_signature_init},
    {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))dilithium_sign},
    {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))dilithium_verify_init},
    {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))dilithium_verify},
    /* 摘要签名操作 */
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))dilithium_digest_sign_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))dilithium_digest_signverify_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))dilithium_digest_sign_final},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))dilithium_digest_verify_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))dilithium_digest_signverify_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))dilithium_digest_verify_final},
    /* 参数相关操作 */
    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))dilithium_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))dilithium_gettable_ctx_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))dilithium_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))dilithium_settable_ctx_params},
    {OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, (void (*)(void))dilithium_get_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, (void (*)(void))dilithium_gettable_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, (void (*)(void))dilithium_set_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, (void (*)(void))dilithium_settable_ctx_md_params},
    {0, NULL}};
