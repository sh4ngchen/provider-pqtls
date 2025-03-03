/**
 * OpenSSL 3.0 Provider - Caesar Cipher Implementation
 * 
 * 这个文件实现了凯撒密码加密算法。
 * 凯撒密码是一种简单的替换密码，将字母表中的每个字母替换为其后的第n个字母。
 */

#include <string.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <stdio.h>
#include "caesar.h"
#include "../include/implementations.h"

/* Cipher 参数定义 */
static const OSSL_PARAM caesar_cipher_param_types[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_END
};

/* Cipher 上下文参数定义 */
static const OSSL_PARAM caesar_ctx_param_types[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_END
};

/* Cipher 参数获取函数 */
static OSSL_FUNC_cipher_get_params_fn cipher_get_params;
static int cipher_get_params(OSSL_PARAM params[])
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
    CAESAR_CTX *ctx = (CAESAR_CTX *)vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, CAESAR_KEY_LENGTH))
        return 0;
    
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->ivlen))
        return 0;
    
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, CAESAR_BLOCK_SIZE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL) {
        if (ctx->ivlen > p->data_size) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        if (!OSSL_PARAM_set_octet_string(p, ctx->oiv, ctx->ivlen)
            && !OSSL_PARAM_set_octet_ptr(p, &ctx->oiv, ctx->ivlen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL) {
        if (ctx->ivlen > p->data_size) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        if (!OSSL_PARAM_set_octet_string(p, ctx->iv, ctx->ivlen)
            && !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivlen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    return 1;
}

static OSSL_FUNC_cipher_set_ctx_params_fn cipher_set_ctx_params;
static int cipher_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    CAESAR_CTX *ctx = (CAESAR_CTX *)vctx;
    const OSSL_PARAM *p;
    size_t sz;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &sz)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (sz != CAESAR_KEY_LENGTH) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
    }

    return 1;
}

static OSSL_FUNC_cipher_gettable_params_fn cipher_gettable_params;
static const OSSL_PARAM *cipher_gettable_params(void *provctx)
{
    return caesar_cipher_param_types;
}

static OSSL_FUNC_cipher_gettable_ctx_params_fn cipher_gettable_ctx_params;
static const OSSL_PARAM *cipher_gettable_ctx_params(void *ctx, void *provctx)
{
    return caesar_ctx_param_types;
}


static OSSL_FUNC_cipher_settable_ctx_params_fn cipher_settable_ctx_params;
static const OSSL_PARAM *cipher_settable_ctx_params(void *ctx, void *provctx)
{
    return caesar_ctx_param_types;
}

/**
 * 更新IV状态
 */
int update_iv(CAESAR_CTX *ctx)
{
    if (ctx->iv_state == IV_STATE_FINISHED
        || ctx->iv_state == IV_STATE_UNINITIALISED)
        return 0;
    
    if (ctx->iv_state == IV_STATE_BUFFERED) {
        /* 凯撒密码不使用IV，但我们需要维护状态 */
        ctx->iv_state = IV_STATE_COPIED;
    }
    return 1;
}

/**
 * 创建新的凯撒密码上下文
 */
static OSSL_FUNC_cipher_newctx_fn caesar_newctx;
static void *caesar_newctx(void *provctx)
{
    CAESAR_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL) {
        ctx->provctx = provctx;
        ctx->keylen = CAESAR_KEY_LENGTH;
        ctx->ivlen = 0;  /* 凯撒密码不使用IV */
        ctx->enc = 1;    /* 默认为加密模式 */
        ctx->key_set = 0;
        ctx->iv_state = IV_STATE_UNINITIALISED;
        ctx->data_buf_len = 0;
    }
    return ctx;
}

/**
 * 复制凯撒密码上下文
 */
static OSSL_FUNC_cipher_dupctx_fn caesar_dupctx;
static void *caesar_dupctx(void *vctx)
{
    CAESAR_CTX *src = (CAESAR_CTX *)vctx;
    CAESAR_CTX *dst;

    if (src == NULL)
        return NULL;

    dst = OPENSSL_malloc(sizeof(CAESAR_CTX));
    if (dst == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    *dst = *src;
    if (src->key != NULL) {
        dst->key = OPENSSL_malloc(src->keylen);
        if (dst->key == NULL) {
            OPENSSL_free(dst);
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
        memcpy(dst->key, src->key, src->keylen);
    }

    return dst;
}

/**
 * 初始化凯撒密码
 */
static int caesar_init(void *vctx, const unsigned char *key, size_t keylen,
                      const unsigned char *iv, size_t ivlen,
                      const OSSL_PARAM params[], int enc)
{
    CAESAR_CTX *ctx = (CAESAR_CTX *)vctx;
    
    ctx->data_buf_len = 0;
    ctx->enc = enc;

    /* 处理IV（虽然凯撒密码不使用IV，但我们需要兼容接口） */
    if (iv != NULL) {
        if (ivlen > sizeof(ctx->iv)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        ctx->ivlen = ivlen;
        memcpy(ctx->iv, iv, ivlen);
        memcpy(ctx->oiv, iv, ivlen);
        ctx->iv_state = IV_STATE_BUFFERED;
    } else {
        /* 如果没有提供IV，我们设置一个默认的IV状态 */
        ctx->iv_state = IV_STATE_BUFFERED;
    }

    /* 处理密钥 */
    if (key != NULL) {
        if (keylen != CAESAR_KEY_LENGTH) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        
        /* 释放旧密钥 */
        if (ctx->key != NULL)
            OPENSSL_free(ctx->key);
            
        /* 复制新密钥 */
        ctx->key = OPENSSL_malloc(keylen);
        if (ctx->key == NULL) {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return 0;
        }
            
        memcpy(ctx->key, key, keylen);
        ctx->keylen = keylen;
        ctx->shift = key[0] % 26;  /* 确保位移在0-25范围内 */
        ctx->key_set = 1;
    } else if (!ctx->key_set) {
        /* 如果没有提供密钥，并且之前也没有设置密钥，则使用默认密钥 */
        unsigned char default_key = 3; /* 默认位移为3 */
        ctx->key = OPENSSL_malloc(1);
        if (ctx->key == NULL) {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        
        ctx->key[0] = default_key;
        ctx->keylen = 1;
        ctx->shift = default_key;
        ctx->key_set = 1;
    }

    return cipher_set_ctx_params(ctx, params);
}

/**
 * 初始化凯撒密码加密
 */
static OSSL_FUNC_cipher_encrypt_init_fn caesar_encrypt_init;
static int caesar_encrypt_init(void *vctx, const unsigned char *key, size_t keylen,
                       const unsigned char *iv, size_t ivlen,
                       const OSSL_PARAM params[])
{
    return caesar_init(vctx, key, keylen, iv, ivlen, params, 1);
}

/**
 * 初始化凯撒密码解密
 */
static OSSL_FUNC_cipher_decrypt_init_fn caesar_decrypt_init;
static int caesar_decrypt_init(void *vctx, const unsigned char *key, size_t keylen,
                       const unsigned char *iv, size_t ivlen,
                       const OSSL_PARAM params[])
{
    return caesar_init(vctx, key, keylen, iv, ivlen, params, 0);
}

/**
 * 执行凯撒密码加密/解密（直接处理）
 */
static OSSL_FUNC_cipher_cipher_fn caesar_cipher;
static int caesar_cipher(void *vctx, unsigned char *out, size_t *outl,
                 size_t outsize, const unsigned char *in, size_t inl)
{
    CAESAR_CTX *ctx = (CAESAR_CTX *)vctx;
    size_t i;
    int shift;

    /* 基本参数检查 */
    if (ctx == NULL || in == NULL) {
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
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    /* 根据加密/解密模式设置位移 */
    shift = ctx->enc ? ctx->shift : (26 - ctx->shift) % 26;

    /* 执行凯撒加密/解密 */
    for (i = 0; i < inl; i++) {
        if (in[i] >= 'A' && in[i] <= 'Z')
            out[i] = 'A' + ((in[i] - 'A' + shift) % 26);
        else if (in[i] >= 'a' && in[i] <= 'z')
            out[i] = 'a' + ((in[i] - 'a' + shift) % 26);
        else
            out[i] = in[i];
    }

    if (outl)
        *outl = inl;
    
    return 1;
}

/**
 * 执行凯撒密码加密/解密（分块处理）
 */
static OSSL_FUNC_cipher_update_fn caesar_update;
static int caesar_update(void *vctx, unsigned char *out, size_t *outl,
                 size_t outsize, const unsigned char *in, size_t inl)
{
    CAESAR_CTX *ctx = (CAESAR_CTX *)vctx;
    size_t nextblocks;
    size_t outlint = 0;

    /* 检查密钥和IV状态 */
    if (!ctx->key_set) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }
    
    if (!update_iv(ctx)) {
        //ERR_raise(ERR_LIB_PROV, PROV_R_IV_NOT_INITIALIZED);
        return 0;
    }

    /* 处理空输入 */
    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    /* 处理缓冲区中的数据 */
    if (ctx->data_buf_len != 0) {
        nextblocks = CAESAR_BLOCK_SIZE - ctx->data_buf_len;
        if (nextblocks > inl)
            nextblocks = inl;
        
        memcpy(ctx->data_buf + ctx->data_buf_len, in, nextblocks);
        ctx->data_buf_len += nextblocks;
        in += nextblocks;
        inl -= nextblocks;
        
        if (ctx->data_buf_len == CAESAR_BLOCK_SIZE) {
            if (outsize < CAESAR_BLOCK_SIZE) {
                ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
                return 0;
            }
            
            /* 处理完整块 */
            if (!caesar_cipher(ctx, out, &outlint, outsize, ctx->data_buf, CAESAR_BLOCK_SIZE)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
                return 0;
            }
            
            ctx->data_buf_len = 0;
            out += outlint;
            outsize -= outlint;
        }
    }

    /* 处理剩余的完整块 */
    nextblocks = inl - (inl % CAESAR_BLOCK_SIZE);
    if (nextblocks > 0) {
        if (outsize < nextblocks) {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
        
        size_t tmp_outl = 0;
        if (!caesar_cipher(ctx, out, &tmp_outl, outsize, in, nextblocks)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
        
        outlint += tmp_outl;
        in += nextblocks;
        inl -= nextblocks;
        out += tmp_outl;
        outsize -= tmp_outl;
    }

    /* 处理剩余的不完整块 */
    if (inl > 0) {
        if (inl > CAESAR_BLOCK_SIZE) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
        
        memcpy(ctx->data_buf, in, inl);
        ctx->data_buf_len = inl;
    }

    *outl = outlint;
    return 1;
}

/**
 * 完成凯撒密码加密/解密
 */
static OSSL_FUNC_cipher_final_fn caesar_final;
static int caesar_final(void *vctx, unsigned char *out, size_t *outl,
                size_t outsize)
{
    CAESAR_CTX *ctx = (CAESAR_CTX *)vctx;

    /* 检查密钥和IV状态 */
    if (!ctx->key_set) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }
    
    if (!update_iv(ctx)) {
        //ERR_raise(ERR_LIB_PROV, PROV_R_IV_NOT_INITIALIZED);
        return 0;
    }

    /* 处理缓冲区中的剩余数据 */
    *outl = 0;
    if (ctx->data_buf_len > 0) {
        if (outsize < ctx->data_buf_len) {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
        
        if (!caesar_cipher(ctx, out, outl, outsize, ctx->data_buf, ctx->data_buf_len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
        
        ctx->data_buf_len = 0;
    }

    /* 标记IV状态为已完成 */
    ctx->iv_state = IV_STATE_FINISHED;
    return 1;
}

/**
 * 释放凯撒密码上下文
 */
static OSSL_FUNC_cipher_freectx_fn caesar_freectx;
static void caesar_freectx(void *vctx)
{
    CAESAR_CTX *ctx = (CAESAR_CTX *)vctx;
    if (ctx != NULL) {
        if (ctx->key != NULL)
            OPENSSL_free(ctx->key);
        OPENSSL_clear_free(ctx, sizeof(*ctx));
    }
}

/* Caesar cipher 函数表 */
const OSSL_DISPATCH caesar_cipher_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))caesar_newctx },
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))caesar_dupctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))caesar_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))caesar_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))caesar_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))caesar_final },
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))caesar_cipher },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))caesar_freectx },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))cipher_get_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))cipher_get_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))cipher_set_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))cipher_gettable_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))cipher_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))cipher_settable_ctx_params },
    { 0, NULL }
};