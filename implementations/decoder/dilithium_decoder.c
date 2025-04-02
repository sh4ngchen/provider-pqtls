#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/core_object.h>
#include "../include/implementations.h"
#include "../include/dilithium.h"
#include "../../util/util.h"


/* 1. 创建 decoder 上下文 */
static OSSL_FUNC_decoder_newctx_fn dilithium_decoder_newctx;
static void *dilithium_decoder_newctx(void *provctx)
{
    DILITHIUM_DECODER_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx)
    {
        return NULL;
    }

    // 从provider上下文获取libctx
    ctx->libctx = PROV_CTX_get0_libctx(provctx);
    ctx->keytype_name = "DILITHIUM2"; // 默认为DILITHIUM2

    return ctx;
}

/* 2. 释放 decoder 上下文 */
static OSSL_FUNC_decoder_freectx_fn dilithium_decoder_freectx;
static void dilithium_decoder_freectx(void *ctx)
{
    OPENSSL_free(ctx);
}

/* 3. 确定支持的 selection */
static OSSL_FUNC_decoder_does_selection_fn dilithium_does_selection;
static int dilithium_does_selection(void *ctx, int selection)
{
    return (selection & (OSSL_KEYMGMT_SELECT_PRIVATE_KEY |
                         OSSL_KEYMGMT_SELECT_PUBLIC_KEY |
                         OSSL_KEYMGMT_SELECT_KEYPAIR));
}

/* 从ASN1_OCTET_STRING中提取私钥和公钥 */
static int extract_key_data_from_octet_string(void *ctx, ASN1_OCTET_STRING *oct,
                                              DILITHIUM_KEY *key)
{
    DILITHIUM_DECODER_CTX *dec_ctx = ctx;
    
    if (oct == NULL || key == NULL)
        return 0;

    size_t secret_key_len, public_key_len;
    if (oct->length == pqcrystals_dilithium2_SECRETKEYBYTES + pqcrystals_dilithium2_PUBLICKEYBYTES) {
        secret_key_len = pqcrystals_dilithium2_SECRETKEYBYTES;
        public_key_len = pqcrystals_dilithium2_PUBLICKEYBYTES;
        dec_ctx->keytype_name = "DILITHIUM2";
    } else if (oct->length == pqcrystals_dilithium3_SECRETKEYBYTES + pqcrystals_dilithium3_PUBLICKEYBYTES) {
        secret_key_len = pqcrystals_dilithium3_SECRETKEYBYTES;
        public_key_len = pqcrystals_dilithium3_PUBLICKEYBYTES;
        dec_ctx->keytype_name = "DILITHIUM3";
    } else if (oct->length == pqcrystals_dilithium5_SECRETKEYBYTES + pqcrystals_dilithium5_PUBLICKEYBYTES) {
        secret_key_len = pqcrystals_dilithium5_SECRETKEYBYTES;
        public_key_len = pqcrystals_dilithium5_PUBLICKEYBYTES;
        dec_ctx->keytype_name = "DILITHIUM5";
    } else if (oct->length == pqcrystals_dilithium2_PUBLICKEYBYTES) {
        /* 只包含公钥 */
        secret_key_len = 0;
        public_key_len = pqcrystals_dilithium2_PUBLICKEYBYTES;
        dec_ctx->keytype_name = "DILITHIUM2";
    } else if (oct->length == pqcrystals_dilithium3_PUBLICKEYBYTES) {
        /* 只包含公钥 */
        secret_key_len = 0;
        public_key_len = pqcrystals_dilithium3_PUBLICKEYBYTES;
        dec_ctx->keytype_name = "DILITHIUM3";
    } else if (oct->length == pqcrystals_dilithium5_PUBLICKEYBYTES) {
        /* 只包含公钥 */
        secret_key_len = 0;
        public_key_len = pqcrystals_dilithium5_PUBLICKEYBYTES;
        dec_ctx->keytype_name = "DILITHIUM5";
    } else {
        return 0; /* 不支持的数据长度 */
    }
    if (secret_key_len) {
        key->secret_key = OPENSSL_malloc(secret_key_len);
        if (key->secret_key == NULL)
            return 0;
        memcpy(key->secret_key, oct->data, secret_key_len);
        key->has_private = 1;
        key->secret_key_len = secret_key_len;
    }
    key->public_key = OPENSSL_malloc(public_key_len);
    if (key->public_key == NULL)
        return 0;
    memcpy(key->public_key, oct->data + secret_key_len, public_key_len);
    key->public_key_len = public_key_len;
    key->has_public = 1;
    return 1;
}

/* 从BIO读取DER数据 */
static int dilithium_read_der(OSSL_LIB_CTX *libctx, OSSL_CORE_BIO *cin,
                          unsigned char **der, long *der_len)
{
    BIO *in = BIO_new_from_core_bio(libctx, cin);
    BUF_MEM *buf = NULL;
    int ok = 0;

    if (in == NULL)
        return 0;

    /* 设置BIO以使用内存 */
    if ((buf = BUF_MEM_new()) == NULL)
        goto err;

    /* 将所有数据读入内存 */
    char temp[1024];
    int bytes;

    while ((bytes = BIO_read(in, temp, sizeof(temp))) > 0)
    {
        if (!BUF_MEM_grow_clean(buf, buf->length + bytes))
        {
            goto err;
        }
        memcpy(buf->data + buf->length - bytes, temp, bytes);
    }

    /* 检查是否有足够的数据 */
    if (buf->length <= 0)
        goto err;

    /* 分配内存并复制数据 */
    *der = OPENSSL_malloc(buf->length);
    if (*der == NULL)
        goto err;

    memcpy(*der, buf->data, buf->length);
    *der_len = buf->length;
    ok = 1;

err:
    BUF_MEM_free(buf);
    BIO_free(in);
    return ok;
}

/* 解码DER格式的密钥 */
static OSSL_FUNC_decoder_decode_fn dilithium_decode_der;
static int dilithium_decode_der(void *ctx, OSSL_CORE_BIO *cin, int selection,
                            OSSL_CALLBACK *data_cb, void *data_cbarg,
                            OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    DILITHIUM_DECODER_CTX *dec_ctx = ctx;
    unsigned char *der = NULL;
    long der_len = 0;
    const unsigned char *octs = NULL;
    int octs_len;
    ASN1_OCTET_STRING *oct = NULL;
    const ASN1_OBJECT *algoid;
    DILITHIUM_KEY *key = NULL;
    int ret = 0;

    /* 读取DER数据 */
    if (!dilithium_read_der(dec_ctx->libctx, cin, &der, &der_len))
    {
        return 0;
    }

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
    {
        OPENSSL_free(der);
        return 0;
    }

    key->libctx = dec_ctx->libctx;
    key->references = 1;

    /* 根据选择尝试解码为私钥或公钥 */
    const unsigned char *der_ptr = der;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        PKCS8_PRIV_KEY_INFO *p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &der_ptr, der_len);
        if (p8 != NULL && PKCS8_pkey_get0(&algoid, &octs, &octs_len, NULL, p8))
        {
            /* 尝试从PKCS8中提取的内容解析为ASN1_OCTET_STRING */
            const unsigned char *octs_ptr = octs;
            oct = d2i_ASN1_OCTET_STRING(NULL, &octs_ptr, octs_len);

            if (oct != NULL && extract_key_data_from_octet_string(dec_ctx, oct, key))
            {
                ASN1_OCTET_STRING_free(oct);
                PKCS8_PRIV_KEY_INFO_free(p8);
                OPENSSL_free(der); /* 释放der */

                // 创建参数并调用回调
                OSSL_PARAM params[4];
                int object_type = OSSL_OBJECT_PKEY;

                params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_DATA, &object_type);
                params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, dec_ctx->keytype_name, 0);
                params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, key, sizeof(*key));
                params[3] = OSSL_PARAM_construct_end();

                ret = data_cb(params, data_cbarg);

                if (!ret)
                {
                    /* 释放key资源 */
                    if (key->secret_key)
                        OPENSSL_free(key->secret_key);
                    if (key->public_key)
                        OPENSSL_free(key->public_key);
                    OPENSSL_free(key);
                }
                return ret;
            }
            
            if (oct != NULL)
                ASN1_OCTET_STRING_free(oct);
            PKCS8_PRIV_KEY_INFO_free(p8);
        } else if (p8 != NULL) {
            PKCS8_PRIV_KEY_INFO_free(p8);
        }
    }
    else if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        /* 尝试使用X509_PUBKEY的标准方式解析 */
        X509_PUBKEY *xpub = NULL;
        const unsigned char *der_ptr = der;
        xpub = pltls_d2i_X509_PUBKEY_INTERNAL(&der_ptr, der_len, dec_ctx->libctx);

        if (xpub != NULL && X509_PUBKEY_get0_param(NULL, &octs, &octs_len, NULL, xpub))
        {
            const unsigned char *octs_ptr = octs;
            oct = d2i_ASN1_OCTET_STRING(NULL, &octs_ptr, octs_len);
            
            if (oct != NULL) {
                /* 设置公钥 */
                key->public_key = OPENSSL_malloc(oct->length);
                if (key->public_key != NULL) {
                    memcpy(key->public_key, oct->data, oct->length);
                    key->public_key_len = oct->length;
                    
                    ASN1_OCTET_STRING_free(oct);
                    X509_PUBKEY_free(xpub);
                    
                    // 创建参数并调用回调
                    OSSL_PARAM params[4];
                    int object_type = OSSL_OBJECT_PKEY;

                    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
                    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, dec_ctx->keytype_name, 0);
                    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, key, sizeof(*key));
                    params[3] = OSSL_PARAM_construct_end();

                    ret = data_cb(params, data_cbarg);

                    if (!ret) {
                        OPENSSL_free(key->public_key);
                        OPENSSL_free(key);
                    }

                    OPENSSL_free(der);
                    return ret;
                }
                ASN1_OCTET_STRING_free(oct);
            }
            X509_PUBKEY_free(xpub);
        } else if (xpub != NULL) {
            X509_PUBKEY_free(xpub);
        }
    }

    /* 如果到这里，说明解析失败，清理资源 */
    OPENSSL_free(der);
    if (key->public_key)
        OPENSSL_free(key->public_key);
    if (key->secret_key)
        OPENSSL_free(key->secret_key);
    OPENSSL_free(key);
    
    return 0;  /* 明确返回失败 */
}

/* 5. decoder 方法表 - 增加DER格式解码器 */
const OSSL_DISPATCH dilithium_decoder_der_functions[] = {
    {OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))dilithium_decoder_newctx},
    {OSSL_FUNC_DECODER_FREECTX, (void (*)(void))dilithium_decoder_freectx},
    {OSSL_FUNC_DECODER_DOES_SELECTION, (void (*)(void))dilithium_does_selection},
    {OSSL_FUNC_DECODER_DECODE, (void (*)(void))dilithium_decode_der},
    {0, NULL}};
