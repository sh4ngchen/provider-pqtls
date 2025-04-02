#include <string.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "../include/impl.h"
#include "../include/kyber.h"

/* 通用函数：根据版本获取密钥长度 */
static void set_key_size_by_version(int version, size_t *pubkey_len, size_t *seckey_len)
{
    switch (version) {
    case 512:
        *pubkey_len = pqcrystals_kyber512_PUBLICKEYBYTES;
        *seckey_len = pqcrystals_kyber512_SECRETKEYBYTES;
        break;
    case 768:
        *pubkey_len = pqcrystals_kyber768_PUBLICKEYBYTES;
        *seckey_len = pqcrystals_kyber768_SECRETKEYBYTES;
        break;
    case 1024:
        *pubkey_len = pqcrystals_kyber1024_PUBLICKEYBYTES;
        *seckey_len = pqcrystals_kyber1024_SECRETKEYBYTES;
        break;
    default:
        *pubkey_len = 0;
        *seckey_len = 0;
    }
}

/* 通用Kyber新建密钥函数 */
static void *kyber_newdata(void *provctx, int version)
{
    KYBER_KEY *key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    
    /* 设置版本和对应的密钥长度 */
    key->version = version;
    set_key_size_by_version(version, &key->public_key_len, &key->secret_key_len);
    
    if (key->public_key_len == 0 || key->secret_key_len == 0) {
        OPENSSL_free(key);
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return NULL;
    }
    
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

/* Kyber-512特有的新建密钥函数 */
static OSSL_FUNC_keymgmt_new_fn kyber512_newdata;
static void *kyber512_newdata(void *provctx)
{
    return kyber_newdata(provctx, 512);
}

/* Kyber-768特有的新建密钥函数 */
static OSSL_FUNC_keymgmt_new_fn kyber768_newdata;
static void *kyber768_newdata(void *provctx)
{
    return kyber_newdata(provctx, 768);
}

/* Kyber-1024特有的新建密钥函数 */
static OSSL_FUNC_keymgmt_new_fn kyber1024_newdata;
static void *kyber1024_newdata(void *provctx)
{
    return kyber_newdata(provctx, 1024);
}

/* 通用的释放密钥函数 */
static OSSL_FUNC_keymgmt_free_fn kyber_freedata;
static void kyber_freedata(void *keydata)
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

/* 为每种位数定义别名以符合原接口 */
static OSSL_FUNC_keymgmt_free_fn kyber512_freedata;
static void kyber512_freedata(void *keydata)
{
    kyber_freedata(keydata);
}

static OSSL_FUNC_keymgmt_free_fn kyber768_freedata;
static void kyber768_freedata(void *keydata)
{
    kyber_freedata(keydata);
}

static OSSL_FUNC_keymgmt_free_fn kyber1024_freedata;
static void kyber1024_freedata(void *keydata)
{
    kyber_freedata(keydata);
}

/* 通用的检测密钥是否包含特定组件的函数 */
static OSSL_FUNC_keymgmt_has_fn kyber_has;
static int kyber_has(const void *keydata, int selection)
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

/* 直接使用通用函数作为别名 */
#define kyber512_has kyber_has
#define kyber768_has kyber_has
#define kyber1024_has kyber_has

/* 通用的导入密钥数据函数 */
static OSSL_FUNC_keymgmt_import_fn kyber_import;
static int kyber_import(void *keydata, int selection, const OSSL_PARAM params[])
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

/* 直接使用通用函数作为别名 */
#define kyber512_import kyber_import
#define kyber768_import kyber_import
#define kyber1024_import kyber_import

/* 导出密钥函数 - 根据version确定使用的长度 */
static OSSL_FUNC_keymgmt_export_fn kyber_export;
static int kyber_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    KYBER_KEY *key = (KYBER_KEY *)keydata;
    OSSL_PARAM params[3], *p = params;
    size_t pub_key_len, sec_key_len;
    
    /* 根据版本确定密钥长度 */
    set_key_size_by_version(key->version, &pub_key_len, &sec_key_len);
    
    if (pub_key_len == 0 || sec_key_len == 0) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && key->has_public) {
        *p++ = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY, key->public_key, pub_key_len);
    }
    
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && key->has_private) {
        *p++ = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PRIV_KEY, key->secret_key, sec_key_len);
    }
    
    *p = OSSL_PARAM_construct_end();

    return param_cb(params, cbarg);
}

/* 为特定版本提供导出函数 */
static OSSL_FUNC_keymgmt_export_fn kyber512_export;
static int kyber512_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    KYBER_KEY *key = (KYBER_KEY *)keydata;
    
    /* 确保密钥版本正确 */
    if (key && key->version != 512) {
        key->version = 512;
        set_key_size_by_version(key->version, &key->public_key_len, &key->secret_key_len);
    }
    
    return kyber_export(keydata, selection, param_cb, cbarg);
}

static OSSL_FUNC_keymgmt_export_fn kyber768_export;
static int kyber768_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    KYBER_KEY *key = (KYBER_KEY *)keydata;
    
    /* 确保密钥版本正确 */
    if (key && key->version != 768) {
        key->version = 768;
        set_key_size_by_version(key->version, &key->public_key_len, &key->secret_key_len);
    }
    
    return kyber_export(keydata, selection, param_cb, cbarg);
}

static OSSL_FUNC_keymgmt_export_fn kyber1024_export;
static int kyber1024_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    KYBER_KEY *key = (KYBER_KEY *)keydata;
    
    /* 确保密钥版本正确 */
    if (key && key->version != 1024) {
        key->version = 1024;
        set_key_size_by_version(key->version, &key->public_key_len, &key->secret_key_len);
    }
    
    return kyber_export(keydata, selection, param_cb, cbarg);
}

/* 导入类型定义 - 通用 */
static OSSL_FUNC_keymgmt_import_types_fn kyber_import_types;
static const OSSL_PARAM *kyber_import_types(int selection)
{
    static const OSSL_PARAM import_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    return import_types;
}

/* 直接使用通用函数作为别名 */
#define kyber512_import_types kyber_import_types
#define kyber768_import_types kyber_import_types
#define kyber1024_import_types kyber_import_types

/* 导出类型定义 - 通用 */
static OSSL_FUNC_keymgmt_export_types_fn kyber_export_types;
static const OSSL_PARAM *kyber_export_types(int selection)
{
    static const OSSL_PARAM export_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    return export_types;
}

/* 直接使用通用函数作为别名 */
#define kyber512_export_types kyber_export_types
#define kyber768_export_types kyber_export_types
#define kyber1024_export_types kyber_export_types

/* 密钥生成初始化 - 根据不同位数 */
static void *kyber_gen_init(void *provctx, int selection, const OSSL_PARAM params[], int version)
{
    KYBER_GEN_CTX *gctx = OPENSSL_zalloc(sizeof(*gctx));
    if (gctx == NULL)
        return NULL;

    gctx->selection = selection;
    gctx->version = version;
    
    /* 设置密钥长度 */
    set_key_size_by_version(version, &gctx->public_key_len, &gctx->secret_key_len);
    
    if (gctx->public_key_len == 0 || gctx->secret_key_len == 0) {
        OPENSSL_free(gctx);
        return NULL;
    }

    return gctx;
}

static OSSL_FUNC_keymgmt_gen_init_fn kyber512_gen_init;
static void *kyber512_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    return kyber_gen_init(provctx, selection, params, 512);
}

static OSSL_FUNC_keymgmt_gen_init_fn kyber768_gen_init;
static void *kyber768_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    return kyber_gen_init(provctx, selection, params, 768);
}

static OSSL_FUNC_keymgmt_gen_init_fn kyber1024_gen_init;
static void *kyber1024_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    return kyber_gen_init(provctx, selection, params, 1024);
}

/* 密钥生成函数 - 统一实现 */
static OSSL_FUNC_keymgmt_gen_fn kyber_gen;
static void *kyber_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    KYBER_KEY *key = NULL;
    KYBER_GEN_CTX *gctx = (KYBER_GEN_CTX *)genctx;
    int ret = 0;
    
    if (!gctx)
        return NULL;
        
    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        return NULL;
    
    // 从genctx获取密钥长度和版本
    key->version = gctx->version;
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
    
    // 根据密钥版本生成密钥对
    switch(key->version) {
        case 512:
            ret = pqcrystals_kyber512_ref_keypair(key->public_key, key->secret_key);
            break;
        case 768:
            ret = pqcrystals_kyber768_ref_keypair(key->public_key, key->secret_key);
            break;
        case 1024:
            ret = pqcrystals_kyber1024_ref_keypair(key->public_key, key->secret_key);
            break;
        default:
            ret = -1;
    }
    
    if (ret != 0) {
        OPENSSL_free(key->public_key);
        OPENSSL_free(key->secret_key);
        OPENSSL_free(key);
        return NULL;
    }

    key->has_public = 1;
    key->has_private = 1;

    return key;
}

/* 为特定版本提供生成密钥函数封装 */
static OSSL_FUNC_keymgmt_gen_fn kyber512_gen;
static void *kyber512_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    KYBER_GEN_CTX *gctx = (KYBER_GEN_CTX *)genctx;
    if (gctx)
        gctx->version = 512;
    return kyber_gen(genctx, osslcb, cbarg);
}

static OSSL_FUNC_keymgmt_gen_fn kyber768_gen;
static void *kyber768_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    KYBER_GEN_CTX *gctx = (KYBER_GEN_CTX *)genctx;
    if (gctx)
        gctx->version = 768;
    return kyber_gen(genctx, osslcb, cbarg);
}

static OSSL_FUNC_keymgmt_gen_fn kyber1024_gen;
static void *kyber1024_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    KYBER_GEN_CTX *gctx = (KYBER_GEN_CTX *)genctx;
    if (gctx)
        gctx->version = 1024;
    return kyber_gen(genctx, osslcb, cbarg);
}

/* 密钥生成清理 - 通用 */
static OSSL_FUNC_keymgmt_gen_cleanup_fn kyber_gen_cleanup;
static void kyber_gen_cleanup(void *genctx)
{
    KYBER_GEN_CTX *gctx = (KYBER_GEN_CTX *)genctx;
    if (gctx != NULL) {
        OPENSSL_free(gctx);
    }
}

/* 直接使用通用函数作为别名 */
#define kyber512_gen_cleanup kyber_gen_cleanup
#define kyber768_gen_cleanup kyber_gen_cleanup
#define kyber1024_gen_cleanup kyber_gen_cleanup

/* 密钥加载 - 通用 */
static OSSL_FUNC_keymgmt_load_fn kyber_load;
static void *kyber_load(const void *reference, size_t reference_sz)
{
    KYBER_KEY *src = (KYBER_KEY *)reference;
    KYBER_KEY *dst = NULL;
    
    if (reference_sz != sizeof(KYBER_KEY) || src == NULL)
        return NULL;
        
    // 创建新的密钥对象
    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    
    // 复制基本字段，包括版本
    dst->version = src->version;
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

/* 直接使用通用函数作为别名 */
#define kyber512_load kyber_load
#define kyber768_load kyber_load
#define kyber1024_load kyber_load

/* 函数表 - 依然保留三个不同的，每个对应不同位数 */
const OSSL_DISPATCH kyber512_keymgmt_functions[] = {
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

const OSSL_DISPATCH kyber768_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))kyber768_newdata },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))kyber768_freedata },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))kyber768_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))kyber768_import },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))kyber768_export },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))kyber768_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))kyber768_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))kyber768_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))kyber768_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))kyber768_export_types },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))kyber768_load },
    { 0, NULL }
};

const OSSL_DISPATCH kyber1024_keymgmt_functions[] = {
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
