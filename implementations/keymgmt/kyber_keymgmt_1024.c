#include <string.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "../include/implementations.h"
#include "../include/kyber.h"

static OSSL_FUNC_keymgmt_new_fn kyber1024_newdata;
static void *kyber1024_newdata(void *provctx)
{
    KYBER_KEY *key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    
    key->public_key_len = pqcrystals_kyber1024_PUBLICKEYBYTES;
    key->secret_key_len = pqcrystals_kyber1024_SECRETKEYBYTES;
    
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

static OSSL_FUNC_keymgmt_free_fn kyber1024_freedata;
static void kyber1024_freedata(void *keydata)
{
    KYBER_KEY *key = (KYBER_KEY *)keydata;
    if (key != NULL) {
        // 释放动态分配的内存
        OPENSSL_free(key->public_key);
        OPENSSL_free(key->secret_key);
        OPENSSL_free(key);
    }
}

static OSSL_FUNC_keymgmt_has_fn kyber1024_has;
static int kyber1024_has(const void *keydata, int selection)
{
    const KYBER_KEY *key = (const KYBER_KEY *)keydata;
    int ok = 1;

    if (key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && key->has_public;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && key->has_private;

    return ok;
}

static OSSL_FUNC_keymgmt_import_fn kyber1024_import;
static int kyber1024_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    KYBER_KEY *key = (KYBER_KEY *)keydata;
    const OSSL_PARAM *param_pub_key = NULL, *param_priv_key = NULL;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        param_pub_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        param_priv_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);

    if (param_pub_key != NULL) {
        if (param_pub_key->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
            
        if (param_pub_key->data_size == key->public_key_len) {
            memcpy(key->public_key, param_pub_key->data, key->public_key_len);
            key->has_public = 1;
        }
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
        if (param_priv_key->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
            
        if (param_priv_key->data_size == key->secret_key_len) {
            memcpy(key->secret_key, param_priv_key->data, key->secret_key_len);
            key->has_private = 1;
        }
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

static OSSL_FUNC_keymgmt_export_fn kyber1024_export;
static int kyber1024_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    KYBER_KEY *key = (KYBER_KEY *)keydata;
    OSSL_PARAM params[3], *p = params;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && key->has_public) {
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, key->public_key, pqcrystals_kyber1024_PUBLICKEYBYTES);
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && key->has_private) {
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, key->secret_key, pqcrystals_kyber1024_SECRETKEYBYTES);
    }
    *p = OSSL_PARAM_construct_end();

    return param_cb(params, cbarg);
}

static OSSL_FUNC_keymgmt_import_types_fn kyber1024_import_types;
static const OSSL_PARAM *kyber1024_import_types(int selection)
{
    static const OSSL_PARAM import_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    return import_types;
}

static OSSL_FUNC_keymgmt_export_types_fn kyber1024_export_types;
static const OSSL_PARAM *kyber1024_export_types(int selection)
{
    static const OSSL_PARAM export_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    return export_types;
}

static OSSL_FUNC_keymgmt_gen_init_fn kyber1024_gen_init;
static void *kyber1024_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    KYBER_GEN_CTX *gctx = OPENSSL_zalloc(sizeof(*gctx));
    if (gctx == NULL)
        return NULL;

    gctx->selection = selection;
    gctx->public_key_len = pqcrystals_kyber1024_PUBLICKEYBYTES;
    gctx->secret_key_len = pqcrystals_kyber1024_SECRETKEYBYTES;

    return gctx;
}

static OSSL_FUNC_keymgmt_gen_fn kyber1024_gen;
static void *kyber1024_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    KYBER_KEY *key = NULL;
    KYBER_GEN_CTX *gctx = (KYBER_GEN_CTX *)genctx;
    
    if (!gctx)
        return NULL;
        
    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        return NULL;
    
    key->public_key_len = gctx->public_key_len;
    key->secret_key_len = gctx->secret_key_len;
    
    key->public_key = OPENSSL_malloc(key->public_key_len);
    key->secret_key = OPENSSL_malloc(key->secret_key_len);
    
    if (key->public_key == NULL || key->secret_key == NULL) {
        OPENSSL_free(key->public_key);
        OPENSSL_free(key->secret_key);
        OPENSSL_free(key);
        return NULL;
    }
    
    if (pqcrystals_kyber1024_ref_keypair(key->public_key, key->secret_key) != 0) {
        OPENSSL_free(key->public_key);
        OPENSSL_free(key->secret_key);
        OPENSSL_free(key);
        return NULL;
    }

    key->has_public = 1;
    key->has_private = 1;

    return key;
}

static OSSL_FUNC_keymgmt_gen_cleanup_fn kyber1024_gen_cleanup;
static void kyber1024_gen_cleanup(void *genctx)
{
    KYBER_GEN_CTX *gctx = (KYBER_GEN_CTX *)genctx;
    if (gctx != NULL) {
        OPENSSL_free(gctx);
    }
}

static OSSL_FUNC_keymgmt_load_fn kyber1024_load;
static void *kyber1024_load(const void *reference, size_t reference_sz)
{
    KYBER_KEY *src = (KYBER_KEY *)reference;
    KYBER_KEY *dst = NULL;
    
    if (reference_sz != sizeof(KYBER_KEY) || src == NULL)
        return NULL;
        
    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    
    dst->public_key_len = src->public_key_len;
    dst->secret_key_len = src->secret_key_len;
    dst->has_public = 0;
    dst->has_private = 0;
    
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

const OSSL_DISPATCH kyber_keymgmt_1024_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))kyber1024_newdata },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))kyber1024_freedata },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))kyber1024_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))kyber1024_import },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))kyber1024_export },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))kyber1024_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))kyber1024_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))kyber1024_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))kyber1024_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))kyber1024_export_types },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))kyber1024_load },
    { 0, NULL }
};