#include <string.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/param_build.h>
#include "../include/impl.h"
#include "../include/dilithium.h"

int dilithium_param_build_set_octet_string(OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                                            const char *key,
                                            const unsigned char *data,
                                            size_t data_len) {
    if (bld != NULL)
        return OSSL_PARAM_BLD_push_octet_string(bld, key, data, data_len);

    p = OSSL_PARAM_locate(p, key);
    if (p != NULL)
        return OSSL_PARAM_set_octet_string(p, data, data_len);
    return 1;
}


static DILITHIUM_KEY *dilithium_key_new(OSSL_LIB_CTX *libctx, int version)
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
static DILITHIUM_KEY *dilithium_key_dup(DILITHIUM_KEY *key)
{
    if (key == NULL)
        return NULL;

    DILITHIUM_KEY *new_key = OPENSSL_zalloc(sizeof(DILITHIUM_KEY));
    if (new_key == NULL)
        return NULL;

    new_key->libctx = key->libctx;
    new_key->version = key->version;
    new_key->public_key_len = key->public_key_len;
    new_key->secret_key_len = key->secret_key_len;
    new_key->sig_len = key->sig_len;
    new_key->has_public = key->has_public;
    new_key->has_private = key->has_private;

    if (key->public_key != NULL) {
        new_key->public_key = OPENSSL_malloc(key->public_key_len);
        if (new_key->public_key == NULL) {
            OPENSSL_free(new_key);
            return NULL;
        }
        memcpy(new_key->public_key, key->public_key, key->public_key_len);
    }

    if (key->secret_key != NULL) {
        new_key->secret_key = OPENSSL_secure_malloc(key->secret_key_len);
        if (new_key->secret_key == NULL) {
            OPENSSL_free(new_key->public_key);
            OPENSSL_free(new_key);
            return NULL;
        }
        memcpy(new_key->secret_key, key->secret_key, key->secret_key_len);
    }

    return new_key;
}

/* 释放密钥结构 */
static void dilithium_key_free(DILITHIUM_KEY *key)
{
    if (key == NULL)
        return;

    if (key->secret_key != NULL) {
        OPENSSL_clear_free(key->secret_key, key->secret_key_len);
        key->secret_key = NULL;
    }

    if (key->public_key != NULL) {
        OPENSSL_free(key->public_key);
        key->public_key = NULL;
    }

    OPENSSL_free(key);
}

/* 创建一个空的 Dilithium 密钥 */
static void *dilithium2_newkey(void *provctx)
{
    return dilithium_key_new(PROV_CTX_get0_libctx(provctx), 2);
}

static void *dilithium3_newkey(void *provctx)
{
    return dilithium_key_new(PROV_CTX_get0_libctx(provctx), 3);
}

static void *dilithium5_newkey(void *provctx)
{
    return dilithium_key_new(PROV_CTX_get0_libctx(provctx), 5);
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
        key->tls_name = "dilithium2";
        if (pqcrystals_dilithium2_ref_keypair(key->public_key, key->secret_key) != 0)
            goto err;
        break;
    case 3:
        key->tls_name = "dilithium3";
        if (pqcrystals_dilithium3_ref_keypair(key->public_key, key->secret_key) != 0)
            goto err;
        break;
    case 5:
        key->tls_name = "dilithium5";
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
        key = dilithium_key_dup(ctx->key);
        return key;
    }

    key = dilithium_key_new(PROV_CTX_get0_libctx(ctx->provctx), ctx->version);
    if (key == NULL)
        return NULL;

    /* 生成密钥对 */
    if (dilithium_gen(key) == 0) {
        dilithium_key_free(key);
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

int dilithium_key_to_params(const DILITHIUM_KEY *key, OSSL_PARAM_BLD *tmpl,
                            OSSL_PARAM *params, int include_private)
{
    int ret = 0;

    if (key == NULL)
        return 0;

    if (key->public_key != NULL) {
        OSSL_PARAM *p = NULL;
        if (tmpl == NULL) {
            p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
        }

        if (p != NULL || tmpl != NULL) {
            if (key->public_key_len == 0 || !dilithium_param_build_set_octet_string(
                                                tmpl, p, OSSL_PKEY_PARAM_PUB_KEY,
                                                key->public_key, key->public_key_len))
                goto err;
        }
    }
    if (key->secret_key != NULL && include_private) {
        OSSL_PARAM *p = NULL;
        if (tmpl == NULL) {
            p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
        }

        if (p != NULL || tmpl != NULL) {
            if (key->secret_key_len == 0 || !dilithium_param_build_set_octet_string(
                                                tmpl, p, OSSL_PKEY_PARAM_PRIV_KEY,
                                                key->secret_key, key->secret_key_len))
                goto err;
        }
    }
    ret = 1;
err:
    return ret;
}

static int dilithium_export(DILITHIUM_KEY *keydata, int selection,
                           OSSL_CALLBACK *param_cb, void *cbarg)
{
    DILITHIUM_KEY *key = (DILITHIUM_KEY *)keydata;
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    int ok = 1;

    if (key == NULL || param_cb == NULL)
        return 0;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int include_private =
            selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;

        ok = ok && dilithium_key_to_params(key, tmpl, NULL, include_private);
    }

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL) {
        ok = 0;
        goto err;
    }

    ok = ok & param_cb(params, cbarg);
    OSSL_PARAM_free(params);
err:
    OSSL_PARAM_BLD_free(tmpl);
    return ok;
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

    if (((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) &&
        ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)) {
        if ((key1->secret_key == NULL && key2->secret_key != NULL) ||
            (key1->secret_key != NULL && key2->secret_key == NULL) ||
            ((key1->tls_name != NULL && key2->tls_name != NULL) &&
             strcmp(key1->tls_name, key2->tls_name))) {
            ok = 0;
        } else {
            ok = ((key1->secret_key == NULL && key2->secret_key == NULL) ||
                  ((key1->secret_key != NULL) &&
                   CRYPTO_memcmp(key1->secret_key, key2->secret_key,
                                 key1->secret_key_len) == 0));
        }
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if ((key1->public_key == NULL && key2->public_key != NULL) ||
            (key1->public_key != NULL && key2->public_key == NULL) ||
            ((key1->tls_name != NULL && key2->tls_name != NULL) &&
             strcmp(key1->tls_name, key2->tls_name))) {
            // special case now: If domain parameter matching
            // requested, consider private key match sufficient:
            ok = ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) &&
                 (key1->secret_key != NULL && key2->secret_key != NULL) &&
                 (CRYPTO_memcmp(key1->secret_key, key2->secret_key,
                                key1->secret_key_len) == 0);
        } else {
            ok = ok && ((key1->public_key == NULL && key2->public_key == NULL) ||
                        ((key1->public_key != NULL) &&
                         CRYPTO_memcmp(key1->public_key, key2->public_key,
                                       key1->public_key_len) == 0));
        }
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
    if (p != NULL && !OSSL_PARAM_set_int(p, security_bits))
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
    DILITHIUM_KEY *key = NULL;
    if (reference_sz == sizeof(key)){
        key = *(DILITHIUM_KEY **)reference;
        *(DILITHIUM_KEY **)reference = NULL;
        return key;
    }
    return NULL;
}

/* 密钥管理方法定义 - Dilithium2 */
const OSSL_DISPATCH dilithium2_keymgmt_functions[] = {
    /* 构造/析构函数 */
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))dilithium2_newkey },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))dilithium_key_free },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))dilithium_key_dup },

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
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))dilithium_key_free },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))dilithium_key_dup },

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
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))dilithium_key_free },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))dilithium_key_dup },

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
