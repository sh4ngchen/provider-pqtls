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
#include <openssl/bio.h>
#include <openssl/objects.h>
#include "impl/include/impl.h"
#include "provider.h"

static OSSL_FUNC_provider_gettable_params_fn provider_gettable_params;
static OSSL_FUNC_provider_get_params_fn provider_get_params;
static OSSL_FUNC_provider_query_operation_fn provider_query;
extern OSSL_FUNC_provider_get_capabilities_fn pq_provider_get_capabilities;

static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

#define PQ_OID_SIGALG_CNT 6
const char *pq_oid_sigalg_list[PQ_OID_SIGALG_CNT] = {
    "1.3.6.1.4.1.2.267.7.4.4",
    "dilithium2",
    "1.3.6.1.4.1.2.267.7.6.5",
    "dilithium3",
    "1.3.6.1.4.1.2.267.7.8.7",
    "dilithium5"
};

#define PQ_OID_KEMALG_CNT 6
const char *pq_oid_kemalg_list[PQ_OID_KEMALG_CNT] = {
    "1.3.6.1.4.1.2.267.8.2.2",
    "kyber512",
    "1.3.6.1.4.1.2.267.8.3.3",
    "kyber768",
    "1.3.6.1.4.1.2.267.8.4.4",
    "kyber1024"
};

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
    OSSL_PARAM_END};

/* Provider 参数获取函数 */
static const OSSL_PARAM *provider_gettable_params(void *provctx)
{
    return provider_param_types;
}

static int provider_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL PQ-TLS Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "1.0.0-dev"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL PQ-TLS Provider v1.0.0-dev"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1)) // provider is always running
        return 0;
    return 1;
}

/* Provider 实现 */
static const OSSL_ALGORITHM provider_keymgmt[] = {
    // Kyber:1.3.6.1.4.1.2.267.8
    {"kyber512:1.3.6.1.4.1.2.267.8.2.2", "provider=pqtls", kyber512_keymgmt_functions, "Kyber Key Management Implementation"},
    {"kyber768:1.3.6.1.4.1.2.267.8.3.3", "provider=pqtls", kyber768_keymgmt_functions, "Kyber Key Management Implementation"},
    {"kyber1024:1.3.6.1.4.1.2.267.8.4.4", "provider=pqtls", kyber1024_keymgmt_functions, "Kyber Key Management Implementation"},
    // Dilithium:1.3.6.1.4.1.2.267.7
    {"dilithium2:1.3.6.1.4.1.2.267.7.4.4", "provider=pqtls", dilithium2_keymgmt_functions, "Dilithium Key Management Implementation"},
    {"dilithium3:1.3.6.1.4.1.2.267.7.6.5", "provider=pqtls", dilithium3_keymgmt_functions, "Dilithium Key Management Implementation"},
    {"dilithium5:1.3.6.1.4.1.2.267.7.8.7", "provider=pqtls", dilithium5_keymgmt_functions, "Dilithium Key Management Implementation"},
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM provider_encoders[] = {
    // Kyber:1.3.6.1.4.1.2.267.8
    {"kyber512:1.3.6.1.4.1.2.267.8.2.2", "provider=pqtls,output=PEM,structure=privatekeyinfo", kyber_encoder_pem_functions, "Kyber Key PEM Encoder"},
    {"kyber512:1.3.6.1.4.1.2.267.8.2.2", "provider=pqtls,output=DER,structure=privatekeyinfo", kyber_encoder_der_functions, "Kyber Key DER Encoder"},
    {"kyber512:1.3.6.1.4.1.2.267.8.2.2", "provider=pqtls,output=PEM,structure=SubjectPublicKeyInfo", kyber_encoder_pem_functions, "Kyber Key PEM Encoder"},
    {"kyber512:1.3.6.1.4.1.2.267.8.2.2", "provider=pqtls,output=DER,structure=SubjectPublicKeyInfo", kyber_encoder_der_functions, "Kyber Key DER Encoder"},
    {"kyber768:1.3.6.1.4.1.2.267.8.3.3", "provider=pqtls,output=PEM,structure=privatekeyinfo", kyber_encoder_pem_functions, "Kyber Key PEM Encoder"},
    {"kyber768:1.3.6.1.4.1.2.267.8.3.3", "provider=pqtls,output=DER,structure=privatekeyinfo", kyber_encoder_der_functions, "Kyber Key DER Encoder"},
    {"kyber768:1.3.6.1.4.1.2.267.8.3.3", "provider=pqtls,output=PEM,structure=SubjectPublicKeyInfo", kyber_encoder_pem_functions, "Kyber Key PEM Encoder"},
    {"kyber768:1.3.6.1.4.1.2.267.8.3.3", "provider=pqtls,output=DER,structure=SubjectPublicKeyInfo", kyber_encoder_der_functions, "Kyber Key DER Encoder"},
    {"kyber1024:1.3.6.1.4.1.2.267.8.4.4", "provider=pqtls,output=PEM,structure=privatekeyinfo", kyber_encoder_pem_functions, "Kyber Key PEM Encoder"},
    {"kyber1024:1.3.6.1.4.1.2.267.8.4.4", "provider=pqtls,output=DER,structure=privatekeyinfo", kyber_encoder_der_functions, "Kyber Key DER Encoder"},
    {"kyber1024:1.3.6.1.4.1.2.267.8.4.4", "provider=pqtls,output=PEM,structure=SubjectPublicKeyInfo", kyber_encoder_pem_functions, "Kyber Key PEM Encoder"},
    {"kyber1024:1.3.6.1.4.1.2.267.8.4.4", "provider=pqtls,output=DER,structure=SubjectPublicKeyInfo", kyber_encoder_der_functions, "Kyber Key DER Encoder"},
    // Dilithium:1.3.6.1.4.1.2.267.7
    {"dilithium2:1.3.6.1.4.1.2.267.7.4.4", "provider=pqtls,output=PEM,structure=privatekeyinfo", dilithium_encoder_pem_functions, "Kyber Key PEM Encoder"},
    {"dilithium2:1.3.6.1.4.1.2.267.7.4.4", "provider=pqtls,output=DER,structure=privatekeyinfo", dilithium_encoder_der_functions, "Kyber Key PEM Encoder"},
    {"dilithium2:1.3.6.1.4.1.2.267.7.4.4", "provider=pqtls,output=PEM,structure=SubjectPublicKeyInfo", dilithium_encoder_pem_functions, "Kyber Key PEM Encoder"},
    {"dilithium2:1.3.6.1.4.1.2.267.7.4.4", "provider=pqtls,output=DER,structure=SubjectPublicKeyInfo", dilithium_encoder_der_functions, "Kyber Key PEM Encoder"},
    {"dilithium3:1.3.6.1.4.1.2.267.7.6.5", "provider=pqtls,output=PEM,structure=privatekeyinfo", dilithium_encoder_pem_functions, "Kyber Key PEM Encoder"},
    {"dilithium3:1.3.6.1.4.1.2.267.7.6.5", "provider=pqtls,output=DER,structure=privatekeyinfo", dilithium_encoder_der_functions, "Kyber Key PEM Encoder"},
    {"dilithium3:1.3.6.1.4.1.2.267.7.6.5", "provider=pqtls,output=PEM,structure=SubjectPublicKeyInfo", dilithium_encoder_pem_functions, "Kyber Key PEM Encoder"},
    {"dilithium3:1.3.6.1.4.1.2.267.7.6.5", "provider=pqtls,output=DER,structure=SubjectPublicKeyInfo", dilithium_encoder_der_functions, "Kyber Key PEM Encoder"},
    {"dilithium5:1.3.6.1.4.1.2.267.7.8.7", "provider=pqtls,output=PEM,structure=privatekeyinfo", dilithium_encoder_pem_functions, "Kyber Key PEM Encoder"},
    {"dilithium5:1.3.6.1.4.1.2.267.7.8.7", "provider=pqtls,output=DER,structure=privatekeyinfo", dilithium_encoder_der_functions, "Kyber Key PEM Encoder"},
    {"dilithium5:1.3.6.1.4.1.2.267.7.8.7", "provider=pqtls,output=PEM,structure=SubjectPublicKeyInfo", dilithium_encoder_pem_functions, "Kyber Key PEM Encoder"},
    {"dilithium5:1.3.6.1.4.1.2.267.7.8.7", "provider=pqtls,output=DER,structure=SubjectPublicKeyInfo", dilithium_encoder_der_functions, "Kyber Key PEM Encoder"},

    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM provider_decoders[] = {
    {"kyber512:1.3.6.1.4.1.2.267.8.2.2", "provider=pqtls,input=DER,structure=privatekeyinfo", kyber_decoder_der_functions, "Kyber Key DER Decoder"},
    {"kyber512:1.3.6.1.4.1.2.267.8.2.2", "provider=pqtls,input=DER,structure=SubjectPublicKeyInfo", kyber_decoder_der_functions, "Kyber Key DER Decoder"},
    {"kyber768:1.3.6.1.4.1.2.267.8.3.3", "provider=pqtls,input=DER,structure=privatekeyinfo", kyber_decoder_der_functions, "Kyber Key DER Decoder"},
    {"kyber768:1.3.6.1.4.1.2.267.8.3.3", "provider=pqtls,input=DER,structure=SubjectPublicKeyInfo", kyber_decoder_der_functions, "Kyber Key DER Decoder"},
    {"kyber1024:1.3.6.1.4.1.2.267.8.4.4", "provider=pqtls,input=DER,structure=privatekeyinfo", kyber_decoder_der_functions, "Kyber Key DER Decoder"},
    {"kyber1024:1.3.6.1.4.1.2.267.8.4.4", "provider=pqtls,input=DER,structure=SubjectPublicKeyInfo", kyber_decoder_der_functions, "Kyber Key DER Decoder"},
    // 添加 Dilithium 解码器
    {"dilithium2:1.3.6.1.4.1.2.267.7.4.4", "provider=pqtls,input=DER,structure=privatekeyinfo", dilithium_decoder_der_functions, "Dilithium Key DER Decoder"},
    {"dilithium2:1.3.6.1.4.1.2.267.7.4.4", "provider=pqtls,input=DER,structure=SubjectPublicKeyInfo", dilithium_decoder_der_functions, "Dilithium Key DER Decoder"},
    {"dilithium3:1.3.6.1.4.1.2.267.7.6.5", "provider=pqtls,input=DER,structure=privatekeyinfo", dilithium_decoder_der_functions, "Dilithium Key DER Decoder"},
    {"dilithium3:1.3.6.1.4.1.2.267.7.6.5", "provider=pqtls,input=DER,structure=SubjectPublicKeyInfo", dilithium_decoder_der_functions, "Dilithium Key DER Decoder"},
    {"dilithium5:1.3.6.1.4.1.2.267.7.8.7", "provider=pqtls,input=DER,structure=privatekeyinfo", dilithium_decoder_der_functions, "Dilithium Key DER Decoder"},
    {"dilithium5:1.3.6.1.4.1.2.267.7.8.7", "provider=pqtls,input=DER,structure=SubjectPublicKeyInfo", dilithium_decoder_der_functions, "Dilithium Key DER Decoder"},
    {NULL, NULL, NULL, NULL}};

// 添加 Dilithium 签名算法
static const OSSL_ALGORITHM provider_signatures[] = {
    {"dilithium2:1.3.6.1.4.1.2.267.7.4.4", "provider=pqtls", dilithium2_signature_functions, "Dilithium Signature Implementation"},
    {"dilithium3:1.3.6.1.4.1.2.267.7.6.5", "provider=pqtls", dilithium3_signature_functions, "Dilithium Signature Implementation"},
    {"dilithium5:1.3.6.1.4.1.2.267.7.8.7", "provider=pqtls", dilithium5_signature_functions, "Dilithium Signature Implementation"},
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM provider_kems[] = {
    {"KYBER512:1.3.6.1.4.1.2.267.8.2.2", "provider=pqtls", kyber512_kem_functions, "Kyber Kem"},
    {"KYBER768:1.3.6.1.4.1.2.267.8.3.3", "provider=pqtls", kyber768_kem_functions, "Kyber Kem"},
    {"KYBER1024:1.3.6.1.4.1.2.267.8.4.4", "provider=pqtls", kyber1024_kem_functions, "Kyber Kem"},
    {NULL, NULL, NULL, NULL}};

/**
 * 查询provider支持的算法
 */
static const OSSL_ALGORITHM *provider_query(void *provctx, int operation_id,
                                         int *no_cache)
{
    *no_cache = 0;
    switch (operation_id)
    {
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
static void provider_teardown(void *provctx)
{
    PROV_CTX *ctx = (PROV_CTX *)provctx;

    /* 释放库上下文 */
    if (ctx->libctx != NULL)
        OSSL_LIB_CTX_free(ctx->libctx);

    OPENSSL_free(ctx);
}

static const OSSL_DISPATCH provider_functions[] = {
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))provider_teardown},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))provider_query},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))provider_get_params},
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))provider_gettable_params},
    {OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))provider_get_capabilities},
    {0, NULL}};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    PROV_CTX *ctx;
    const OSSL_DISPATCH *orig_in = in;
    OSSL_FUNC_core_obj_create_fn *c_obj_create = NULL;

    OSSL_FUNC_core_obj_add_sigid_fn *c_obj_add_sigid = NULL;
    OSSL_LIB_CTX *libctx = NULL;
    int i, rc = 0;

    for (; in->function_id != 0; in++)
    {
        switch (in->function_id)
        {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_FUNC_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_OBJ_CREATE:
            c_obj_create = OSSL_FUNC_core_obj_create(in);
            break;
        case OSSL_FUNC_CORE_OBJ_ADD_SIGID:
            c_obj_add_sigid = OSSL_FUNC_core_obj_add_sigid(in);
            break;
        /* Just ignore anything we don't understand */
        default:
            break;
        }
    }

    // we need these functions:
    if (c_obj_create == NULL || c_obj_add_sigid == NULL || c_get_params == NULL)
        goto end_init;

    for (i = 0; i < PQ_OID_SIGALG_CNT; i += 2)
    {
        c_obj_create(handle, pq_oid_sigalg_list[i], pq_oid_sigalg_list[i + 1], pq_oid_sigalg_list[i + 1]);
        c_obj_add_sigid(handle, pq_oid_sigalg_list[i], pq_oid_sigalg_list[i + 1], pq_oid_sigalg_list[i + 1]);
        if (OBJ_sn2nid(pq_oid_sigalg_list[i + 1]) == 0) {
            fprintf(stderr, "Failed to register OID %s\n", pq_oid_sigalg_list[i + 1]);
            goto end_init;
        }
    }

    for (i = 0; i < PQ_OID_KEMALG_CNT; i += 2)
    {
        c_obj_create(handle, pq_oid_kemalg_list[i], pq_oid_kemalg_list[i + 1], pq_oid_kemalg_list[i + 1]);
        if (OBJ_sn2nid(pq_oid_kemalg_list[i + 1]) == 0) {
            fprintf(stderr, "Failed to register OID %s\n", pq_oid_kemalg_list[i + 1]);
            goto end_init;
        }
    }

    ctx = OPENSSL_malloc(sizeof(PROV_CTX));
    if (ctx == NULL){
        rc = 0;
        goto end_init;
    }
        
    ctx->handle = handle;
    ctx->libctx = OSSL_LIB_CTX_new_child(handle, orig_in);
    if (ctx->libctx == NULL) {
        rc = 0;
        goto end_init;
    }
    
    *out = provider_functions;
    *provctx = ctx;
    rc = 1;

end_init:
    if (!rc) {
        if (libctx) {
            OSSL_LIB_CTX_free(libctx);
        }
        if (provctx && *provctx) {
            provider_teardown(*provctx);
            *provctx = NULL;
        }
    }
    return rc;
}
