#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include "../include/impl.h"
#include "../include/dilithium.h"
#include "../../util/util.h"

/* 1. 创建 encoder 上下文 */
static OSSL_FUNC_encoder_newctx_fn dilithium_encoder_newctx;
static void *dilithium_encoder_newctx(void *provctx) {
    DILITHIUM_ENCODER_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx) {
        return NULL;
    }
    
    // 从provider上下文获取libctx
    ctx->libctx = PROV_CTX_get0_libctx(provctx);
    
    return ctx;
}

/* 2. 释放 encoder 上下文 */
static OSSL_FUNC_encoder_freectx_fn dilithium_encoder_freectx;
static void dilithium_encoder_freectx(void *ctx) {
    OPENSSL_free(ctx);
}

/* 3. 确定支持的 selection */
static OSSL_FUNC_encoder_does_selection_fn dilithium_does_selection;
static int dilithium_does_selection(void *ctx, int selection) {
    return (selection & (OSSL_KEYMGMT_SELECT_PRIVATE_KEY |
                         OSSL_KEYMGMT_SELECT_PUBLIC_KEY |
                         OSSL_KEYMGMT_SELECT_KEYPAIR));
}

/* 将DILITHIUM_KEY转换为DER格式 - 保存私钥和公钥 */
static int dilithium_key_to_der(void *ctx, const DILITHIUM_KEY *dilithium_key, unsigned char **der) {
    DILITHIUM_ENCODER_CTX *enc_ctx = ctx;
    ASN1_OCTET_STRING *oct = NULL;
    unsigned char *buf = NULL;
    size_t buflen;
    int derlen = -1;
    
    if (!dilithium_key || !der) {
        return -1;
    }

    if (enc_ctx->only_pub) {
        buflen = dilithium_key->public_key_len;
        buf = OPENSSL_secure_malloc(buflen);
        if (buf == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            return -1;
        }
        memcpy(buf, dilithium_key->public_key, buflen);
    } else {
        buflen = dilithium_key->secret_key_len + dilithium_key->public_key_len;
        buf = OPENSSL_secure_malloc(buflen);
        if (buf == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            return -1;
        }
        memcpy(buf, dilithium_key->secret_key, dilithium_key->secret_key_len);
        memcpy(buf + dilithium_key->secret_key_len, dilithium_key->public_key, dilithium_key->public_key_len);
    }
    
    /* 创建ASN1_OCTET_STRING */
    oct = ASN1_OCTET_STRING_new();
    if (oct == NULL) {
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
        OPENSSL_secure_clear_free(buf, buflen);
        return -1;
    }
    
    if (!ASN1_OCTET_STRING_set(oct, buf, buflen)) {
        ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);
        ASN1_OCTET_STRING_free(oct);
        OPENSSL_secure_clear_free(buf, buflen);
        return -1;
    }
    
    derlen = i2d_ASN1_OCTET_STRING(oct, der);
    if (derlen <= 0) {
        ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);
    }
    
    /* 清理中间数据 */
    ASN1_OCTET_STRING_free(oct);
    OPENSSL_secure_clear_free(buf, buflen);
    
    return derlen;
}

/* 将密钥写入PKCS8_PRIV_KEY_INFO结构体 */
static PKCS8_PRIV_KEY_INFO *dilithium_key_to_pkcs8(void *ctx, const DILITHIUM_KEY *dilithium_key) {
    DILITHIUM_ENCODER_CTX *enc_ctx = ctx;
    int nid = 0;

    if (!dilithium_key) {
        return NULL;
    }

    switch (dilithium_key->version) {
        case 2:
            nid = OBJ_txt2nid("dilithium2");
            break;
        case 3:
            nid = OBJ_txt2nid("dilithium3");
            break;
        case 5:
            nid = OBJ_txt2nid("dilithium5");
            break;
        default:
            return NULL;
    }
    
    
    PKCS8_PRIV_KEY_INFO *p8info = PKCS8_PRIV_KEY_INFO_new();
    if (!p8info) {
        return NULL;
    }
    
    unsigned char *der = NULL;
    int derlen = dilithium_key_to_der(enc_ctx, dilithium_key, &der);
    if (derlen <= 0) {
        PKCS8_PRIV_KEY_INFO_free(p8info);
        return NULL;
    }
    
    if (!PKCS8_pkey_set0(p8info, OBJ_nid2obj(nid), 0, V_ASN1_NULL, NULL, der, derlen)) {
        PKCS8_PRIV_KEY_INFO_free(p8info);
        OPENSSL_free(der);
        return NULL;
    }

    return p8info;
}

/* 将DILITHIUM_KEY转换为X509_PUBKEY结构体 */
static X509_PUBKEY *dilithium_key_to_x509_pubkey(void *ctx, const DILITHIUM_KEY *dilithium_key) {
    DILITHIUM_ENCODER_CTX *enc_ctx = ctx;
    X509_PUBKEY *pubkey = NULL;
    int derlen, nid;
    unsigned char *der = NULL;
    
    if (!dilithium_key || !dilithium_key->public_key) {
        return NULL;
    }

    switch (dilithium_key->version) {
        case 2:
            nid = OBJ_txt2nid("dilithium2");
            break;
        case 3:
            nid = OBJ_txt2nid("dilithium3");
            break;
        case 5:
            nid = OBJ_txt2nid("dilithium5");
            break;
        default:
            return NULL;
    }
    
    /* 确保仅处理公钥 */
    enc_ctx->only_pub = 1;

    if (((pubkey = X509_PUBKEY_new()) == NULL) || (derlen = dilithium_key_to_der(enc_ctx, dilithium_key, &der)) <= 0 ||
        !X509_PUBKEY_set0_param(pubkey, OBJ_nid2obj(nid), V_ASN1_NULL, NULL, der, derlen)) {
        OPENSSL_free(der);
        X509_PUBKEY_free(pubkey);
        pubkey = NULL;
        return NULL;
    }
    
    return pubkey;
}

/* 4. 编码密钥 (PEM格式) */
static OSSL_FUNC_encoder_encode_fn dilithium_encode_pem;
static int dilithium_encode_pem(void *ctx, OSSL_CORE_BIO *out, const void *keydata, const OSSL_PARAM obj_abstract[],
                        int selection, OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg) {
    DILITHIUM_ENCODER_CTX *enc_ctx = ctx;
    
    if (!keydata || !out) {
        return 0;
    }

    BIO *bio = BIO_new_from_core_bio(enc_ctx->libctx, out);
    if (!bio) {
        return 0;
    }

    const DILITHIUM_KEY *dilithium_key = keydata;

    /* PEM 格式输出 */
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        enc_ctx->only_pub = 0;
        PKCS8_PRIV_KEY_INFO *p8info = dilithium_key_to_pkcs8(enc_ctx, dilithium_key);
        if (!p8info) {
            BIO_free(bio);
            return 0;
        }
        
        if (!PEM_write_bio_PKCS8_PRIV_KEY_INFO(bio, p8info)) {
            BIO_free(bio);
            PKCS8_PRIV_KEY_INFO_free(p8info);
            return 0;
        }

        PKCS8_PRIV_KEY_INFO_free(p8info);
    } else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        enc_ctx->only_pub = 1;
        X509_PUBKEY *pubkey = dilithium_key_to_x509_pubkey(enc_ctx, dilithium_key);
        if (!pubkey) {
            BIO_free(bio);
            return 0;
        }
        
        if (!PEM_write_bio_X509_PUBKEY(bio, pubkey)) {
            BIO_free(bio);
            X509_PUBKEY_free(pubkey);
            return 0;
        }

        X509_PUBKEY_free(pubkey);
    }

    BIO_free_all(bio);
    return 1;
}

/* 4. 编码密钥 (DER格式) */
static OSSL_FUNC_encoder_encode_fn dilithium_encode_der;
static int dilithium_encode_der(void *ctx, OSSL_CORE_BIO *out, const void *keydata, const OSSL_PARAM obj_abstract[],
                        int selection, OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg) {
    DILITHIUM_ENCODER_CTX *enc_ctx = ctx;
    
    if (!keydata || !out) {
        return 0;
    }

    BIO *bio = BIO_new_from_core_bio(enc_ctx->libctx, out);
    if (!bio) {
        return 0;
    }

    const DILITHIUM_KEY *dilithium_key = keydata;

    /* DER 格式输出 */
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        enc_ctx->only_pub = 0;
        PKCS8_PRIV_KEY_INFO *p8info = dilithium_key_to_pkcs8(enc_ctx, dilithium_key);
        if (!p8info) {
            BIO_free(bio);
            return 0;
        }
        i2d_PKCS8_PRIV_KEY_INFO_bio(bio, p8info);
        PKCS8_PRIV_KEY_INFO_free(p8info);
    } else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        enc_ctx->only_pub = 1;
        X509_PUBKEY *pubkey = dilithium_key_to_x509_pubkey(enc_ctx, dilithium_key);
        if (!pubkey) {
            BIO_free(bio);
            return 0;
        }
        
        if (!i2d_X509_PUBKEY_bio(bio, pubkey)) {
            BIO_free(bio);
            X509_PUBKEY_free(pubkey);
            return 0;
        }
        
        X509_PUBKEY_free(pubkey);
    }

    BIO_free_all(bio);
    return 1;
}

/* 5. PEM encoder 方法表 */
const OSSL_DISPATCH dilithium_encoder_pem_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))dilithium_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))dilithium_encoder_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))dilithium_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))dilithium_encode_pem },
    { 0, NULL }
};

/* 6. DER encoder 方法表 */
const OSSL_DISPATCH dilithium_encoder_der_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))dilithium_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))dilithium_encoder_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))dilithium_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))dilithium_encode_der },
    { 0, NULL }
};
