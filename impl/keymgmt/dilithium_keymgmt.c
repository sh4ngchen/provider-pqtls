#include <string.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "../include/impl.h"
#include "../include/dilithium.h"

/* 创建一个新的 Dilithium 密钥结构，根据版本设置不同参数 */
static DILITHIUM_KEY *DILITHIUM_KEY_new(OSSL_LIB_CTX *libctx, int version)
{
    DILITHIUM_KEY *key = OPENSSL_zalloc(sizeof(DILITHIUM_KEY));

    if (key != NULL) {
        key->libctx = libctx;
        key->references = 1;
        
        /* 根据版本设置密钥长度 */
        switch (version) {
        case 2:
            key->public_key_len = pqcrystals_dilithium2_PUBLICKEYBYTES;
            key->secret_key_len = pqcrystals_dilithium2_SECRETKEYBYTES;
            key->sig_len = pqcrystals_dilithium2_BYTES;
            break;
        case 3:
            key->public_key_len = pqcrystals_dilithium3_PUBLICKEYBYTES;
            key->secret_key_len = pqcrystals_dilithium3_SECRETKEYBYTES;
            key->sig_len = pqcrystals_dilithium3_BYTES;
            break;
        case 5:
            key->public_key_len = pqcrystals_dilithium5_PUBLICKEYBYTES;
            key->secret_key_len = pqcrystals_dilithium5_SECRETKEYBYTES;
            key->sig_len = pqcrystals_dilithium5_BYTES;
            break;
        default:
            OPENSSL_free(key);
            return NULL;
        }
        key->version = version;
    }
    return key;
}

/* 增加密钥的引用计数 */
static DILITHIUM_KEY *DILITHIUM_KEY_dup(DILITHIUM_KEY *key)
{
    if (key != NULL)
        ++key->references;
    return key;
}

/* 释放密钥结构 */
static void DILITHIUM_KEY_free(DILITHIUM_KEY *key)
{
    if (key != NULL && --key->references == 0) {
        OPENSSL_clear_free(key->secret_key, key->secret_key_len);
        OPENSSL_free(key->public_key);
        OPENSSL_free(key);
    }
}

/* 创建一个空的 Dilithium 密钥 */
static void *dilithium2_newkey(void *provctx)
{
    return DILITHIUM_KEY_new(PROV_CTX_get0_libctx(provctx), 2);
}

static void *dilithium3_newkey(void *provctx)
{
    return DILITHIUM_KEY_new(PROV_CTX_get0_libctx(provctx), 3);
}

static void *dilithium5_newkey(void *provctx)
{
    return DILITHIUM_KEY_new(PROV_CTX_get0_libctx(provctx), 5);
}

/* 生成 Dilithium 密钥对 */
static int dilithium_gen(DILITHIUM_KEY *key)
{
    int ret = 0;

    if (key == NULL)
        return 0;

    /* 分配内存 */
    if (key->public_key == NULL)
        key->public_key = OPENSSL_malloc(key->public_key_len);
    if (key->secret_key == NULL)
        key->secret_key = OPENSSL_secure_malloc(key->secret_key_len);

    if (key->public_key == NULL || key->secret_key == NULL)
        goto err;

    /* 根据版本生成密钥对 */
    switch (key->version) {
    case 2:
        if (pqcrystals_dilithium2_ref_keypair(key->public_key, key->secret_key) != 0)
            goto err;
        break;
    case 3:
        if (pqcrystals_dilithium3_ref_keypair(key->public_key, key->secret_key) != 0)
            goto err;
        break;
    case 5:
        if (pqcrystals_dilithium5_ref_keypair(key->public_key, key->secret_key) != 0)
            goto err;
        break;
    default:
        goto err;
    }

    ret = 1;
    key->has_public = 1;
    key->has_private = 1;

err:
    if (ret == 0) {
        OPENSSL_free(key->public_key);
        key->public_key = NULL;
        OPENSSL_clear_free(key->secret_key, key->secret_key_len);
        key->secret_key = NULL;
    }
    return ret;
}

/* 密钥生成接口 */
static void *dilithium_gen_init(void *provctx, int selection, int version)
{
    DILITHIUM_GEN_CTX *genctx = OPENSSL_zalloc(sizeof(DILITHIUM_GEN_CTX));

    if (genctx == NULL)
        return NULL;

    genctx->provctx = provctx;
    genctx->selection = selection;
    genctx->version = version;
    return genctx;
}

static void *dilithium2_gen_init(void *provctx, int selection)
{
    return dilithium_gen_init(provctx, selection, 2);
}

static void *dilithium3_gen_init(void *provctx, int selection)
{
    return dilithium_gen_init(provctx, selection, 3);
}

static void *dilithium5_gen_init(void *provctx, int selection)
{
    return dilithium_gen_init(provctx, selection, 5);
}

static int dilithium_gen_set_template(void *genctx, void *templ)
{
    DILITHIUM_GEN_CTX *ctx = genctx;

    if (ctx == NULL || templ == NULL)
        return 0;

    ctx->key = templ;
    return 1;
}

static int dilithium_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    /* 目前没有参数需要设置 */
    return 1;
}

static const OSSL_PARAM *dilithium_gen_settable_params(void *genctx, void *provctx)
{
    static const OSSL_PARAM settable[] = {
        /* 目前没有可设置的参数 */
        OSSL_PARAM_END
    };
    return settable;
}

static void *dilithium_gen_cleanup(void *genctx)
{
    DILITHIUM_GEN_CTX *ctx = genctx;

    if (ctx == NULL)
        return NULL;
    OPENSSL_free(ctx);
    return NULL;
}

static void *dilithium_gen_generate(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
    DILITHIUM_GEN_CTX *ctx = genctx;
    DILITHIUM_KEY *key;

    if (ctx == NULL)
        return NULL;

    if (ctx->key != NULL) {
        key = DILITHIUM_KEY_dup(ctx->key);
        return key;
    }

    key = DILITHIUM_KEY_new(PROV_CTX_get0_libctx(ctx->provctx), ctx->version);
    if (key == NULL)
        return NULL;

    /* 生成密钥对 */
    if (dilithium_gen(key) == 0) {
        DILITHIUM_KEY_free(key);
        return NULL;
    }

    return key;
}

/* 导入导出 */
static int dilithium_import(DILITHIUM_KEY *key, int keytype, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if (key == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p != NULL) {
        if (p->data_size != key->public_key_len)
            return 0;
        if (key->public_key == NULL)
            key->public_key = OPENSSL_malloc(key->public_key_len);
        if (key->public_key == NULL)
            return 0;
        memcpy(key->public_key, p->data, key->public_key_len);
        key->has_public = 1;
    }

    if ((keytype & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p != NULL) {
            if (p->data_size != key->secret_key_len)
                return 0;
            if (key->secret_key == NULL)
                key->secret_key = OPENSSL_secure_malloc(key->secret_key_len);
            if (key->secret_key == NULL)
                return 0;
            memcpy(key->secret_key, p->data, key->secret_key_len);
            key->has_private = 1;
        }
    }

    return 1;
}

static int dilithium_export(DILITHIUM_KEY *key, int keytype,
                           OSSL_CALLBACK *param_cb, void *cbarg)
{
    OSSL_PARAM params[3], *p = params;

    if (key == NULL)
        return 0;

    if ((keytype & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && key->public_key != NULL) {
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                               key->public_key,
                                               key->public_key_len);
    }

    if ((keytype & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && key->secret_key != NULL) {
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                               key->secret_key,
                                               key->secret_key_len);
    }

    *p = OSSL_PARAM_construct_end();

    return param_cb(params, cbarg);
}

/* 密钥检查 */
static int dilithium_check(DILITHIUM_KEY *key)
{
    return (key != NULL && (key->public_key != NULL || key->secret_key != NULL));
}

static int dilithium_has(const DILITHIUM_KEY *key, int selection)
{
    int ok = 0;

    if (key != NULL) {
        ok = 1;

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok &= (key->public_key != NULL);

        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok &= (key->secret_key != NULL);
    }

    return ok;
}

static int dilithium_match(const DILITHIUM_KEY *key1, const DILITHIUM_KEY *key2,
                         int selection)
{
    int ok = 1;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (key1->public_key == NULL || key2->public_key == NULL)
            ok = 0;
        else if (key1->public_key_len != key2->public_key_len)
            ok = 0;
        else if (memcmp(key1->public_key, key2->public_key, key1->public_key_len) != 0)
            ok = 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (key1->secret_key == NULL || key2->secret_key == NULL)
            ok = 0;
        else if (key1->secret_key_len != key2->secret_key_len)
            ok = 0;
        else if (memcmp(key1->secret_key, key2->secret_key, key1->secret_key_len) != 0)
            ok = 0;
    }

    return ok;
}

/* 版本特定的参数获取 */
static int dilithium_get_params(DILITHIUM_KEY *key, OSSL_PARAM params[], int security_bits)
{
    OSSL_PARAM *p;

    if (key == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, key->public_key_len * 8))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL && !OSSL_PARAM_set_int(p, key->sig_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, security_bits))
        return 0;

    return 1;
}

static int dilithium2_get_params(DILITHIUM_KEY *key, OSSL_PARAM params[])
{
    return dilithium_get_params(key, params, 128); /* NIST Level 2 */
}

static int dilithium3_get_params(DILITHIUM_KEY *key, OSSL_PARAM params[])
{
    return dilithium_get_params(key, params, 192); /* NIST Level 3 */
}

static int dilithium5_get_params(DILITHIUM_KEY *key, OSSL_PARAM params[])
{
    return dilithium_get_params(key, params, 256); /* NIST Level 5 */
}

static const OSSL_PARAM *dilithium_gettable_params(void *provctx)
{
    static OSSL_PARAM gettable[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_END
    };
    return gettable;
}

static const OSSL_PARAM *dilithium_settable_params(void *provctx)
{
    static OSSL_PARAM settable[] = {
        /* 目前没有可设置的参数 */
        OSSL_PARAM_END
    };
    return settable;
}

static int dilithium_set_params(DILITHIUM_KEY *key, const OSSL_PARAM params[])
{
    /* 目前没有可设置的参数 */
    return 1;
}

/* 定义支持的导入类型 */
static const OSSL_PARAM *dilithium_import_types(int selection)
{
    static const OSSL_PARAM import_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    return import_types;
}

/* 定义支持的导出类型 */
static const OSSL_PARAM *dilithium_export_types(int selection)
{
    static const OSSL_PARAM export_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    return export_types;
}

/* 加载密钥 */
static void *dilithium_load(const void *reference, size_t reference_sz)
{
    const DILITHIUM_KEY *src = (const DILITHIUM_KEY *)reference;
    DILITHIUM_KEY *dst = NULL;
    
    if (reference_sz != sizeof(DILITHIUM_KEY) || src == NULL)
        return NULL;
        
    /* 创建新的密钥对象 */
    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    
    /* 初始化基本字段 */
    dst->libctx = src->libctx;
    dst->public_key_len = src->public_key_len;
    dst->secret_key_len = src->secret_key_len;
    dst->sig_len = src->sig_len;
    dst->version = src->version;
    dst->references = 1;
    dst->has_public = 0;
    dst->has_private = 0;
    
    /* 复制公钥（如果存在） */
    if (src->public_key != NULL) {
        dst->public_key = OPENSSL_malloc(src->public_key_len);
        if (dst->public_key == NULL) {
            OPENSSL_free(dst);
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
        memcpy(dst->public_key, src->public_key, src->public_key_len);
        dst->has_public = 1;
    }
    
    /* 复制私钥（如果存在） */
    if (src->secret_key != NULL) {
        dst->secret_key = OPENSSL_secure_malloc(src->secret_key_len);
        if (dst->secret_key == NULL) {
            OPENSSL_free(dst->public_key);
            OPENSSL_free(dst);
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
        memcpy(dst->secret_key, src->secret_key, src->secret_key_len);
        dst->has_private = 1;
    }
    
    return dst;
}

/* 密钥管理方法定义 - Dilithium2 */
const OSSL_DISPATCH dilithium2_keymgmt_functions[] = {
    /* 构造/析构函数 */
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))dilithium2_newkey },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))DILITHIUM_KEY_free },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))DILITHIUM_KEY_dup },

    /* 密钥生成相关函数 */
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))dilithium2_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))dilithium_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))dilithium_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))dilithium_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))dilithium_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))dilithium_gen_generate },

    /* 密钥获取/设置参数函数 */
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))dilithium2_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))dilithium_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))dilithium_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))dilithium_settable_params },

    /* 导入/导出函数 */
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))dilithium_import },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))dilithium_export },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))dilithium_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))dilithium_export_types },

    /* 密钥检查函数 */
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))dilithium_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))dilithium_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))dilithium_check },
    
    /* 密钥加载函数 */
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))dilithium_load },
    
    { 0, NULL }
};

/* 密钥管理方法定义 - Dilithium3 */
const OSSL_DISPATCH dilithium3_keymgmt_functions[] = {
    /* 构造/析构函数 */
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))dilithium3_newkey },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))DILITHIUM_KEY_free },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))DILITHIUM_KEY_dup },

    /* 密钥生成相关函数 */
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))dilithium3_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))dilithium_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))dilithium_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))dilithium_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))dilithium_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))dilithium_gen_generate },

    /* 密钥获取/设置参数函数 */
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))dilithium3_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))dilithium_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))dilithium_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))dilithium_settable_params },

    /* 导入/导出函数 */
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))dilithium_import },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))dilithium_export },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))dilithium_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))dilithium_export_types },

    /* 密钥检查函数 */
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))dilithium_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))dilithium_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))dilithium_check },
    
    /* 密钥加载函数 */
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))dilithium_load },
    
    { 0, NULL }
};

/* 密钥管理方法定义 - Dilithium5 */
const OSSL_DISPATCH dilithium5_keymgmt_functions[] = {
    /* 构造/析构函数 */
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))dilithium5_newkey },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))DILITHIUM_KEY_free },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))DILITHIUM_KEY_dup },

    /* 密钥生成相关函数 */
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))dilithium5_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))dilithium_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))dilithium_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))dilithium_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))dilithium_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))dilithium_gen_generate },

    /* 密钥获取/设置参数函数 */
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))dilithium5_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))dilithium_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))dilithium_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))dilithium_settable_params },

    /* 导入/导出函数 */
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))dilithium_import },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))dilithium_export },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))dilithium_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))dilithium_export_types },

    /* 密钥检查函数 */
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))dilithium_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))dilithium_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))dilithium_check },
    
    /* 密钥加载函数 */
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))dilithium_load },
    
    { 0, NULL }
};
