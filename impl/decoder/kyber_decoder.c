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
#include "../include/impl.h"
#include "../include/kyber.h"
#include "../../util/util.h"

/* 1. 创建 decoder 上下文 */
static OSSL_FUNC_decoder_newctx_fn kyber_decoder_newctx;
static void *kyber_decoder_newctx(void *provctx)
{
    KYBER_DECODER_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx)
    {
        return NULL;
    }

    // 从provider上下文获取libctx
    ctx->libctx = PROV_CTX_get0_libctx(provctx);

    return ctx;
}

/* 2. 释放 decoder 上下文 */
static OSSL_FUNC_decoder_freectx_fn kyber_decoder_freectx;
static void kyber_decoder_freectx(void *ctx)
{
    OPENSSL_free(ctx);
}

/* 3. 确定支持的 selection */
static OSSL_FUNC_decoder_does_selection_fn kyber_does_selection;
static int kyber_does_selection(void *ctx, int selection)
{
    return (selection & (OSSL_KEYMGMT_SELECT_PRIVATE_KEY |
                         OSSL_KEYMGMT_SELECT_PUBLIC_KEY |
                         OSSL_KEYMGMT_SELECT_KEYPAIR));
}

/* 从ASN1_OCTET_STRING中提取私钥和公钥 */
static int extract_key_data_from_octet_string(void *ctx, ASN1_OCTET_STRING *oct,
                                              KYBER_KEY *key)
{
    KYBER_DECODER_CTX *dec_ctx = ctx;
    if (oct == NULL || key == NULL)
        return 0;
    /* 从ASN1_OCTET_STRING中提取私钥和可能的公钥数据 */
    size_t secret_key_len, public_key_len;
    /* 根据数据长度估计是哪种Kyber参数 */
    if (oct->length == pqcrystals_kyber1024_SECRETKEYBYTES + pqcrystals_kyber1024_PUBLICKEYBYTES)
    { /* Kyber-1024 */
        secret_key_len = pqcrystals_kyber1024_SECRETKEYBYTES;
        public_key_len = pqcrystals_kyber1024_PUBLICKEYBYTES;
        dec_ctx->keytype_name = "KYBER1024";
    }
    else if (oct->length == pqcrystals_kyber768_SECRETKEYBYTES + pqcrystals_kyber768_PUBLICKEYBYTES)
    { /* Kyber-768 */
        secret_key_len = pqcrystals_kyber768_SECRETKEYBYTES;
        public_key_len = pqcrystals_kyber768_PUBLICKEYBYTES;
        dec_ctx->keytype_name = "KYBER768";
    }
    else if (oct->length == pqcrystals_kyber512_SECRETKEYBYTES + pqcrystals_kyber512_PUBLICKEYBYTES)
    { /* Kyber-512 */
        secret_key_len = pqcrystals_kyber512_SECRETKEYBYTES;
        public_key_len = pqcrystals_kyber512_PUBLICKEYBYTES;
        dec_ctx->keytype_name = "KYBER512";
    }
    else
    {
        return 0;
    }
    key->secret_key = OPENSSL_malloc(secret_key_len);
    if (key->secret_key == NULL)
        return 0;

    memcpy(key->secret_key, oct->data, secret_key_len);
    key->secret_key_len = secret_key_len;
    key->has_private = 1;

    if (oct->length > secret_key_len)
    {
        key->public_key = OPENSSL_malloc(public_key_len);
        if (key->public_key == NULL)
        {
            /* 清理并返回失败 */
            OPENSSL_free(key->secret_key);
            key->secret_key = NULL;
            key->has_private = 0;
            return 0;
        }

        memcpy(key->public_key, oct->data + secret_key_len, public_key_len);
        key->public_key_len = public_key_len;
        key->has_public = 1;
    }

    return 1;
}

/* 从BIO读取DER数据 */
static int kyber_read_der(OSSL_LIB_CTX *libctx, OSSL_CORE_BIO *cin,
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
static OSSL_FUNC_decoder_decode_fn kyber_decode_der;
static int kyber_decode_der(void *ctx, OSSL_CORE_BIO *cin, int selection,
                            OSSL_CALLBACK *data_cb, void *data_cbarg,
                            OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    KYBER_DECODER_CTX *dec_ctx = ctx;
    unsigned char *der = NULL;
    long der_len = 0;
    const unsigned char *octs = NULL;
    int octs_len;
    ASN1_OCTET_STRING *oct = NULL;
    const ASN1_OBJECT *algoid;
    KYBER_KEY *key = NULL;
    int ret = 0;

    /* 读取DER数据 */
    if (!kyber_read_der(dec_ctx->libctx, cin, &der, &der_len))
    {
        return 0;
    }

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
    {
        OPENSSL_free(der);
        return 0;
    }

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

                params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
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
    else if ((selection && OSSL_KEYMGMT_SELECT_PUBLIC_KEY != 0))
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
                const unsigned char *pk_data = oct->data;
                int pk_len = oct->length;

                /* 根据公钥长度确定Kyber参数 */
                if (pk_len == pqcrystals_kyber1024_PUBLICKEYBYTES)
                {
                    key->public_key = OPENSSL_malloc(pk_len);
                    if (key->public_key != NULL)
                    {
                        memcpy(key->public_key, pk_data, pk_len);
                        key->public_key_len = pk_len;
                        key->has_public = 1;
                        dec_ctx->keytype_name = "KYBER1024";
                    }
                }
                else if (pk_len == pqcrystals_kyber768_PUBLICKEYBYTES)
                {
                    key->public_key = OPENSSL_malloc(pk_len);
                    if (key->public_key != NULL)
                    {
                        memcpy(key->public_key, pk_data, pk_len);
                        key->public_key_len = pk_len;
                        key->has_public = 1;
                        dec_ctx->keytype_name = "KYBER768";
                    }
                }
                else if (pk_len == pqcrystals_kyber512_PUBLICKEYBYTES)
                {
                    key->public_key = OPENSSL_malloc(pk_len);
                    if (key->public_key != NULL)
                    {
                        memcpy(key->public_key, pk_data, pk_len);
                        key->public_key_len = pk_len;
                        key->has_public = 1;
                        dec_ctx->keytype_name = "KYBER512";
                    }
                }
                ASN1_OCTET_STRING_free(oct);
            }
            X509_PUBKEY_free(xpub);

            if (key->has_public)
            {
                // 创建参数并调用回调
                OSSL_PARAM params[4];
                int object_type = OSSL_OBJECT_PKEY;

                params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
                params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, dec_ctx->keytype_name, 0);
                params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, key, sizeof(*key));
                params[3] = OSSL_PARAM_construct_end();

                ret = data_cb(params, data_cbarg);

                if (!ret)
                {
                    OPENSSL_free(key->public_key);
                    OPENSSL_free(key);
                }

                OPENSSL_free(der);
                return ret;
            }
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
const OSSL_DISPATCH kyber_decoder_der_functions[] = {
    {OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))kyber_decoder_newctx},
    {OSSL_FUNC_DECODER_FREECTX, (void (*)(void))kyber_decoder_freectx},
    {OSSL_FUNC_DECODER_DOES_SELECTION, (void (*)(void))kyber_does_selection},
    {OSSL_FUNC_DECODER_DECODE, (void (*)(void))kyber_decode_der},
    {0, NULL}};
