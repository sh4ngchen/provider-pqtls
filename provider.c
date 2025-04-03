/**
 * OpenSSL 3.0 Provider - Provider Implementation
 * 
 * 这个文件实现了一个OpenSSL 3.0 provider，提供后量子加密功能。
 */

#include <string.h>
#include <openssl/core_names.h>
#include <openssl/core.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/core_dispatch.h>
#include "impl/include/impl.h"
#include "provider.h"

/* Provider Context 工具函数的实现 */
OSSL_LIB_CTX *PROV_CTX_get0_libctx(const PROV_CTX *ctx)
{
    return ctx->libctx;
}

/* Provider 参数定义 */
static const OSSL_PARAM provider_param_types[] = {
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, NULL, 0),
    OSSL_PARAM_END
};

/* Provider 参数获取函数 */
static const OSSL_PARAM *provider_gettable_params(void *provctx)
{
    return provider_param_types;
}

static OSSL_FUNC_provider_get_params_fn provider_get_params;
static int provider_get_params(void *provctx, OSSL_PARAM params[])
{
    static const char name[] = "Post-Quantum Provider";
    static const char version[] = "1.0.0";
    static const char buildinfo[] = "Post-Quantum Provider v1.0.0";
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, name))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, version))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, buildinfo))
        return 0;
    return 1;
}

/* Provider 实现 */
static const OSSL_ALGORITHM provider_keymgmt[] = {
    // Kyber:1.3.6.1.4.1.2.267.8
    { "KYBER512:1.3.6.1.4.1.2.267.8.2.2", "provider=pqtls", kyber512_keymgmt_functions, "Kyber Key Management Implementation" },
    { "KYBER768:1.3.6.1.4.1.2.267.8.3.3", "provider=pqtls", kyber768_keymgmt_functions, "Kyber Key Management Implementation" },
    { "KYBER1024:1.3.6.1.4.1.2.267.8.4.4", "provider=pqtls", kyber1024_keymgmt_functions, "Kyber Key Management Implementation" },
    // Dilithium:1.3.6.1.4.1.2.267.7
    { "DILITHIUM2:1.3.6.1.4.1.2.267.7.4.4", "provider=pqtls", dilithium2_keymgmt_functions, "Dilithium Key Management Implementation" },
    { "DILITHIUM3:1.3.6.1.4.1.2.267.7.6.5", "provider=pqtls", dilithium3_keymgmt_functions, "Dilithium Key Management Implementation" },
    { "DILITHIUM5:1.3.6.1.4.1.2.267.7.8.7", "provider=pqtls", dilithium5_keymgmt_functions, "Dilithium Key Management Implementation" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM provider_encoders[] = {
    // Kyber:1.3.6.1.4.1.2.267.8
    { "KYBER512:1.3.6.1.4.1.2.267.8.2.2", "provider=pqtls,output=PEM,structure=privatekeyinfo", kyber_encoder_pem_functions, "Kyber Key PEM Encoder" },
    { "KYBER512:1.3.6.1.4.1.2.267.8.2.2", "provider=pqtls,output=DER,structure=privatekeyinfo", kyber_encoder_der_functions, "Kyber Key DER Encoder" },
    { "KYBER512:1.3.6.1.4.1.2.267.8.2.2", "provider=pqtls,output=PEM,structure=SubjectPublicKeyInfo", kyber_encoder_pem_functions, "Kyber Key PEM Encoder" },
    { "KYBER512:1.3.6.1.4.1.2.267.8.2.2", "provider=pqtls,output=DER,structure=SubjectPublicKeyInfo", kyber_encoder_der_functions, "Kyber Key DER Encoder" },
    { "KYBER768:1.3.6.1.4.1.2.267.8.3.3", "provider=pqtls,output=PEM,structure=privatekeyinfo", kyber_encoder_pem_functions, "Kyber Key PEM Encoder" },
    { "KYBER768:1.3.6.1.4.1.2.267.8.3.3", "provider=pqtls,output=DER,structure=privatekeyinfo", kyber_encoder_der_functions, "Kyber Key DER Encoder" },
    { "KYBER768:1.3.6.1.4.1.2.267.8.3.3", "provider=pqtls,output=PEM,structure=SubjectPublicKeyInfo", kyber_encoder_pem_functions, "Kyber Key PEM Encoder" },
    { "KYBER768:1.3.6.1.4.1.2.267.8.3.3", "provider=pqtls,output=DER,structure=SubjectPublicKeyInfo", kyber_encoder_der_functions, "Kyber Key DER Encoder" },
    { "KYBER1024:1.3.6.1.4.1.2.267.8.4.4", "provider=pqtls,output=PEM,structure=privatekeyinfo", kyber_encoder_pem_functions, "Kyber Key PEM Encoder" },
    { "KYBER1024:1.3.6.1.4.1.2.267.8.4.4", "provider=pqtls,output=DER,structure=privatekeyinfo", kyber_encoder_der_functions, "Kyber Key DER Encoder" },
    { "KYBER1024:1.3.6.1.4.1.2.267.8.4.4", "provider=pqtls,output=PEM,structure=SubjectPublicKeyInfo", kyber_encoder_pem_functions, "Kyber Key PEM Encoder" },
    { "KYBER1024:1.3.6.1.4.1.2.267.8.4.4", "provider=pqtls,output=DER,structure=SubjectPublicKeyInfo", kyber_encoder_der_functions, "Kyber Key DER Encoder" },
    // Dilithium:1.3.6.1.4.1.2.267.7
    { "DILITHIUM2:1.3.6.1.4.1.2.267.7.4.4", "provider=pqtls,output=PEM,structure=privatekeyinfo", dilithium_encoder_pem_functions, "Kyber Key PEM Encoder"},
    { "DILITHIUM2:1.3.6.1.4.1.2.267.7.4.4", "provider=pqtls,output=DER,structure=privatekeyinfo", dilithium_encoder_der_functions, "Kyber Key PEM Encoder"},
    { "DILITHIUM2:1.3.6.1.4.1.2.267.7.4.4", "provider=pqtls,output=PEM,structure=SubjectPublicKeyInfo", dilithium_encoder_pem_functions, "Kyber Key PEM Encoder"},
    { "DILITHIUM2:1.3.6.1.4.1.2.267.7.4.4", "provider=pqtls,output=DER,structure=SubjectPublicKeyInfo", dilithium_encoder_der_functions, "Kyber Key PEM Encoder"},
    { "DILITHIUM3:1.3.6.1.4.1.2.267.7.6.5", "provider=pqtls,output=PEM,structure=privatekeyinfo", dilithium_encoder_pem_functions, "Kyber Key PEM Encoder"},
    { "DILITHIUM3:1.3.6.1.4.1.2.267.7.6.5", "provider=pqtls,output=DER,structure=privatekeyinfo", dilithium_encoder_der_functions, "Kyber Key PEM Encoder"},
    { "DILITHIUM3:1.3.6.1.4.1.2.267.7.6.5", "provider=pqtls,output=PEM,structure=SubjectPublicKeyInfo", dilithium_encoder_pem_functions, "Kyber Key PEM Encoder"},
    { "DILITHIUM3:1.3.6.1.4.1.2.267.7.6.5", "provider=pqtls,output=DER,structure=SubjectPublicKeyInfo", dilithium_encoder_der_functions, "Kyber Key PEM Encoder"},
    { "DILITHIUM5:1.3.6.1.4.1.2.267.7.8.7", "provider=pqtls,output=PEM,structure=privatekeyinfo", dilithium_encoder_pem_functions, "Kyber Key PEM Encoder"},
    { "DILITHIUM5:1.3.6.1.4.1.2.267.7.8.7", "provider=pqtls,output=DER,structure=privatekeyinfo", dilithium_encoder_der_functions, "Kyber Key PEM Encoder"},
    { "DILITHIUM5:1.3.6.1.4.1.2.267.7.8.7", "provider=pqtls,output=PEM,structure=SubjectPublicKeyInfo", dilithium_encoder_pem_functions, "Kyber Key PEM Encoder"},
    { "DILITHIUM5:1.3.6.1.4.1.2.267.7.8.7", "provider=pqtls,output=DER,structure=SubjectPublicKeyInfo", dilithium_encoder_der_functions, "Kyber Key PEM Encoder"},
    
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM provider_decoders[] = {
    { "KYBER512:1.3.6.1.4.1.2.267.8.2.2", "provider=pqtls,input=DER,structure=privatekeyinfo", kyber_decoder_der_functions, "Kyber Key DER Decoder" },
    { "KYBER512:1.3.6.1.4.1.2.267.8.2.2", "provider=pqtls,input=DER,structure=SubjectPublicKeyInfo", kyber_decoder_der_functions, "Kyber Key DER Decoder" },
    { "KYBER768:1.3.6.1.4.1.2.267.8.3.3", "provider=pqtls,input=DER,structure=privatekeyinfo", kyber_decoder_der_functions, "Kyber Key DER Decoder" },
    { "KYBER768:1.3.6.1.4.1.2.267.8.3.3", "provider=pqtls,input=DER,structure=SubjectPublicKeyInfo", kyber_decoder_der_functions, "Kyber Key DER Decoder" },
    { "KYBER1024:1.3.6.1.4.1.2.267.8.4.4", "provider=pqtls,input=DER,structure=privatekeyinfo", kyber_decoder_der_functions, "Kyber Key DER Decoder" },
    { "KYBER1024:1.3.6.1.4.1.2.267.8.4.4", "provider=pqtls,input=DER,structure=SubjectPublicKeyInfo", kyber_decoder_der_functions, "Kyber Key DER Decoder" },
    // 添加 Dilithium 解码器
    { "DILITHIUM2:1.3.6.1.4.1.2.267.7.4.4", "provider=pqtls,input=DER,structure=privatekeyinfo", dilithium_decoder_der_functions, "Dilithium Key DER Decoder" },
    { "DILITHIUM2:1.3.6.1.4.1.2.267.7.4.4", "provider=pqtls,input=DER,structure=SubjectPublicKeyInfo", dilithium_decoder_der_functions, "Dilithium Key DER Decoder" },
    { "DILITHIUM3:1.3.6.1.4.1.2.267.7.6.5", "provider=pqtls,input=DER,structure=privatekeyinfo", dilithium_decoder_der_functions, "Dilithium Key DER Decoder" },
    { "DILITHIUM3:1.3.6.1.4.1.2.267.7.6.5", "provider=pqtls,input=DER,structure=SubjectPublicKeyInfo", dilithium_decoder_der_functions, "Dilithium Key DER Decoder" },
    { "DILITHIUM5:1.3.6.1.4.1.2.267.7.8.7", "provider=pqtls,input=DER,structure=privatekeyinfo", dilithium_decoder_der_functions, "Dilithium Key DER Decoder" },
    { "DILITHIUM5:1.3.6.1.4.1.2.267.7.8.7", "provider=pqtls,input=DER,structure=SubjectPublicKeyInfo", dilithium_decoder_der_functions, "Dilithium Key DER Decoder" },
    { NULL, NULL, NULL, NULL }
};

// 添加 Dilithium 签名算法
static const OSSL_ALGORITHM provider_signatures[] = {
    { "DILITHIUM2:1.3.6.1.4.1.2.267.7.4.4", "provider=pqtls", dilithium2_signature_functions, "Dilithium Signature Implementation" },
    { "DILITHIUM3:1.3.6.1.4.1.2.267.7.6.5", "provider=pqtls", dilithium3_signature_functions, "Dilithium Signature Implementation" },
    { "DILITHIUM5:1.3.6.1.4.1.2.267.7.8.7", "provider=pqtls", dilithium5_signature_functions, "Dilithium Signature Implementation" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM provider_kems[] = {
    { "KYBER512:1.3.6.1.4.1.2.267.8.2.2", "provider=pqtls", kyber512_kem_functions, "Kyber Kem"},
    { "KYBER768:1.3.6.1.4.1.2.267.8.3.3", "provider=pqtls", kyber768_kem_functions, "Kyber Kem"},
    { "KYBER1024:1.3.6.1.4.1.2.267.8.4.4", "provider=pqtls", kyber1024_kem_functions, "Kyber Kem"},
    { NULL, NULL, NULL, NULL }
};

/**
 * 查询provider支持的算法
 */
static const OSSL_ALGORITHM *local_query(void *provctx, int operation_id,
                                     int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
        case OSSL_OP_KEYMGMT:
            return provider_keymgmt;
        case OSSL_OP_ENCODER:
            return provider_encoders;
        case OSSL_OP_DECODER:
            return provider_decoders;
        case OSSL_OP_KEM:
            return provider_kems;
        case OSSL_OP_SIGNATURE:
            return provider_signatures;
    }
    return NULL;
}

/**
 * 清理provider上下文
 */
static void local_teardown(void *provctx)
{
    PROV_CTX *ctx = (PROV_CTX *)provctx;
    
    /* 释放库上下文 */
    if (ctx->libctx != NULL)
        OSSL_LIB_CTX_free(ctx->libctx);
    
    OPENSSL_free(ctx);
}

/* Provider 入口点 */
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                      const OSSL_DISPATCH *in,
                      const OSSL_DISPATCH **out,
                      void **provctx)
{
    PROV_CTX *ctx;
    const OSSL_DISPATCH *orig_in = in;

    /* 创建provider上下文 */
    ctx = OPENSSL_malloc(sizeof(PROV_CTX));
    if (ctx == NULL)
        return 0;

    ctx->handle = handle;
    
    /* 使用OSSL_LIB_CTX_new_child创建新的库上下文 */
    ctx->libctx = OSSL_LIB_CTX_new_child(handle, orig_in);
    if (ctx->libctx == NULL) {
        OPENSSL_free(ctx);
        return 0;
    }

    /* 设置provider函数表 */
    static const OSSL_DISPATCH provider_functions[] = {
        { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))local_teardown },
        { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))local_query },
        { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))provider_get_params },
        { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))provider_gettable_params },
        { 0, NULL }
    };
    *out = provider_functions;
    *provctx = ctx;

    return 1;
}

