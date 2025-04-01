#include <string.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "../include/implementations.h"
#include "../include/kyber.h"

static OSSL_FUNC_keymgmt_new_fn kyber512_newdata;
static void *kyber512_newdata(void *provctx)
{
    KYBER_KEY *key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    
    key->public_key_len = pqcrystals_kyber512_PUBLICKEYBYTES;
    key->secret_key_len = pqcrystals_kyber512_SECRETKEYBYTES;
    
    // 分配公钥和私钥的内存
    key->public_key = OPENSSL_malloc(key->public_key_len);
    key->secret_key = OPENSSL_malloc(key->secret_key_len);
    
    if (key->public_key == NULL || key->secret_key == NULL) {
        OPENSSL_free(key->public_key);
        OPENSSL_free(key->secret_key);
        OPENSSL_free(key);
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    
    key->has_public = 0;
    key->has_private = 0;
    return key;
}

static OSSL_FUNC_keymgmt_free_fn kyber512_freedata;
static void kyber512_freedata(void *keydata)
{
    if (keydata == NULL) {
        return;  // 提前返回，避免无效操作
    }
    
    KYBER_KEY *key = (KYBER_KEY *)keydata;
    
    // 检查指针有效性再释放
    if (key->public_key != NULL) {
        OPENSSL_free(key->public_key);
        key->public_key = NULL;  // 防止重复释放
    }
    
    if (key->secret_key != NULL) {
        OPENSSL_free(key->secret_key);
        key->secret_key = NULL;  // 防止重复释放
    }
    
    OPENSSL_free(key);
}

static OSSL_FUNC_keymgmt_has_fn kyber512_has;
static int kyber512_has(const void *keydata, int selection)
{
    const KYBER_KEY *key = (const KYBER_KEY *)keydata;
    int ok = 1;

    if (key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && key->has_public;  // 使用标志
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && key->has_private; // 使用标志

    return ok;
}

static OSSL_FUNC_keymgmt_import_fn kyber512_import;
static int kyber512_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    KYBER_KEY *key = (KYBER_KEY *)keydata;
    const OSSL_PARAM *param_pub_key = NULL, *param_priv_key = NULL;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        param_pub_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        param_priv_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);

    if (param_pub_key != NULL) {
        /* 放宽对公钥大小的检查，数据可能来自不同格式 */
        if (param_pub_key->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
            
        /* 如果大小一致，直接复制 */
        if (param_pub_key->data_size == key->public_key_len) {
            memcpy(key->public_key, param_pub_key->data, key->public_key_len);
            key->has_public = 1;
        }
        /* 如果大小不一致但大小合理，考虑重新分配内存 */
        else if (param_pub_key->data_size > 0 && param_pub_key->data_size < 2048) {
            unsigned char *new_pubkey = OPENSSL_realloc(key->public_key, param_pub_key->data_size);
            if (new_pubkey) {
                key->public_key = new_pubkey;
                key->public_key_len = param_pub_key->data_size;
                memcpy(key->public_key, param_pub_key->data, key->public_key_len);
                key->has_public = 1;
            } else {
                return 0;
            }
        } else {
            return 0;
        }
    }

    if (param_priv_key != NULL) {
        /* 放宽对私钥大小的检查，数据可能来自不同格式 */
        if (param_priv_key->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
            
        /* 如果大小一致，直接复制 */
        if (param_priv_key->data_size == key->secret_key_len) {
            memcpy(key->secret_key, param_priv_key->data, key->secret_key_len);
            key->has_private = 1;
        }
        /* 如果大小不一致但大小合理，考虑重新分配内存 */
        else if (param_priv_key->data_size > 0 && param_priv_key->data_size < 4096) {
            unsigned char *new_seckey = OPENSSL_realloc(key->secret_key, param_priv_key->data_size);
            if (new_seckey) {
                key->secret_key = new_seckey;
                key->secret_key_len = param_priv_key->data_size;
                memcpy(key->secret_key, param_priv_key->data, key->secret_key_len);
                key->has_private = 1;
            } else {
                return 0;
            }
        } else {
            return 0;
        }
    }

    return 1;
}

static OSSL_FUNC_keymgmt_export_fn kyber512_export;
static int kyber512_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    KYBER_KEY *key = (KYBER_KEY *)keydata;
    OSSL_PARAM params[3], *p = params;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && key->has_public) {
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, key->public_key, pqcrystals_kyber512_PUBLICKEYBYTES);
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && key->has_private) {
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, key->secret_key, pqcrystals_kyber512_SECRETKEYBYTES);
    }
    *p = OSSL_PARAM_construct_end();

    return param_cb(params, cbarg);
}

static OSSL_FUNC_keymgmt_import_types_fn kyber512_import_types;
static const OSSL_PARAM *kyber512_import_types(int selection)
{
    static const OSSL_PARAM import_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    return import_types;
}

static OSSL_FUNC_keymgmt_export_types_fn kyber512_export_types;
static const OSSL_PARAM *kyber512_export_types(int selection)
{
    static const OSSL_PARAM export_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    return export_types;
}

static OSSL_FUNC_keymgmt_gen_init_fn kyber512_gen_init;
static void *kyber512_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    KYBER_GEN_CTX *gctx = OPENSSL_zalloc(sizeof(*gctx));
    if (gctx == NULL)
        return NULL;

    gctx->selection = selection;
    gctx->public_key_len = pqcrystals_kyber512_PUBLICKEYBYTES;
    gctx->secret_key_len = pqcrystals_kyber512_SECRETKEYBYTES;

    return gctx;
}

static OSSL_FUNC_keymgmt_gen_fn kyber512_gen;
static void *kyber512_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    KYBER_KEY *key = NULL;
    KYBER_GEN_CTX *gctx = (KYBER_GEN_CTX *)genctx;
    
    if (!gctx)
        return NULL;
        
    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        return NULL;
    
    // 从genctx获取密钥长度
    key->public_key_len = gctx->public_key_len;
    key->secret_key_len = gctx->secret_key_len;
    
    // 分配公钥和私钥的内存
    key->public_key = OPENSSL_malloc(key->public_key_len);
    key->secret_key = OPENSSL_malloc(key->secret_key_len);
    
    if (key->public_key == NULL || key->secret_key == NULL) {
        OPENSSL_free(key->public_key);
        OPENSSL_free(key->secret_key);
        OPENSSL_free(key);
        return NULL;
    }
    
    // 生成密钥对
    if (pqcrystals_kyber512_ref_keypair(key->public_key, key->secret_key) != 0) {
        OPENSSL_free(key->public_key);
        OPENSSL_free(key->secret_key);
        OPENSSL_free(key);
        return NULL;
    }

    key->has_public = 1;
    key->has_private = 1;

    return key;
}

static OSSL_FUNC_keymgmt_gen_cleanup_fn kyber512_gen_cleanup;
static void kyber512_gen_cleanup(void *genctx)
{
    KYBER_GEN_CTX *gctx = (KYBER_GEN_CTX *)genctx;
    if (gctx != NULL) {
        OPENSSL_free(gctx);
    }
}

static OSSL_FUNC_keymgmt_load_fn kyber512_load;
static void *kyber512_load(const void *reference, size_t reference_sz)
{
    KYBER_KEY *src = (KYBER_KEY *)reference;
    KYBER_KEY *dst = NULL;
    
    if (reference_sz != sizeof(KYBER_KEY) || src == NULL)
        return NULL;
        
    // 直接创建新的密钥对象，不使用provctx参数
    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    
    // 初始化基本字段
    dst->public_key_len = src->public_key_len;
    dst->secret_key_len = src->secret_key_len;
    dst->has_public = 0;
    dst->has_private = 0;
    
    // 分配并复制公钥（如果存在）
    if (src->has_public && src->public_key != NULL) {
        dst->public_key = OPENSSL_malloc(src->public_key_len);
        if (dst->public_key == NULL) {
            OPENSSL_free(dst);
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
        memcpy(dst->public_key, src->public_key, src->public_key_len);
        dst->has_public = 1;
    } else {
        dst->public_key = NULL;
    }
    
    // 分配并复制私钥（如果存在）
    if (src->has_private && src->secret_key != NULL) {
        dst->secret_key = OPENSSL_malloc(src->secret_key_len);
        if (dst->secret_key == NULL) {
            OPENSSL_free(dst->public_key);
            OPENSSL_free(dst);
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
        memcpy(dst->secret_key, src->secret_key, src->secret_key_len);
        dst->has_private = 1;
    } else {
        dst->secret_key = NULL;
    }
    
    return dst;
}

const OSSL_DISPATCH kyber_keymgmt_512_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))kyber512_newdata },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))kyber512_freedata },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))kyber512_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))kyber512_import },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))kyber512_export },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))kyber512_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))kyber512_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))kyber512_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))kyber512_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))kyber512_export_types },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))kyber512_load },
    { 0, NULL }
};