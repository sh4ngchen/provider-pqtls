/**
 * OpenSSL 3.0 Provider - Kyber KEM Implementation
 * 
 * 这个文件实现了Kyber密钥封装机制(KEM)算法。
 * Kyber是一种后量子密码学算法，基于模格问题的安全性。
 */

#include <string.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdio.h>
#include "kyber.h"
#include "../include/implementations.h"

#ifdef NDEBUG
#define KYBER_PRINTF(a)
#define KYBER_PRINTF2(a, b)
#define KYBER_PRINTF3(a, b, c)
#else
#define KYBER_PRINTF(a)                                                      \
    if (getenv("KYBERKEM"))                                                 \
    printf(a)
#define KYBER_PRINTF2(a, b)                                                 \
    if (getenv("KYBERKEM"))                                                 \
    printf(a, b)
#define KYBER_PRINTF3(a, b, c)                                              \
    if (getenv("KYBERKEM"))                                                 \
    printf(a, b, c)
#endif // NDEBUG

/* Kyber KEM 核心函数声明 */
static int kyber_enc(const unsigned char *seed, const unsigned char *pk,
                     unsigned char *ct, unsigned char *ss);
static int kyber_dec(const unsigned char *ct, const unsigned char *sk,
                     unsigned char *ss);
static int kyber_keygen(unsigned char *pk, unsigned char *sk);

static OSSL_FUNC_kem_newctx_fn kyber_newctx;
static OSSL_FUNC_kem_encapsulate_init_fn kyber_encapsulate_init;
static OSSL_FUNC_kem_encapsulate_fn kyber_encapsulate;
static OSSL_FUNC_kem_decapsulate_init_fn kyber_decapsulate_init;
static OSSL_FUNC_kem_decapsulate_fn kyber_decapsulate;
static OSSL_FUNC_kem_freectx_fn kyber_freectx;

static void *kyber_newctx(void *provctx)
{
    KYBER_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    
    KYBER_PRINTF("Kyber KEM provider called: newctx\n");
    ctx->provctx = provctx;
    ctx->security_level = KYBER_768;  /* 默认使用Kyber-768 */
    
    /* 设置默认参数 */
    ctx->secret_key_len = KYBER_768_SECRET_KEY_LENGTH;
    ctx->public_key_len = KYBER_768_PUBLIC_KEY_LENGTH;
    ctx->ciphertext_len = KYBER_768_CIPHERTEXT_LENGTH;
    ctx->shared_secret_len = KYBER_768_SHARED_SECRET_LENGTH;
    
    /* 分配密钥存储空间 */
    ctx->secret_key = OPENSSL_secure_malloc(ctx->secret_key_len);
    if (ctx->secret_key == NULL) {
        OPENSSL_free(ctx);
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    
    ctx->public_key = OPENSSL_secure_malloc(ctx->public_key_len);
    if (ctx->public_key == NULL) {
        OPENSSL_secure_clear_free(ctx->secret_key, ctx->secret_key_len);
        OPENSSL_free(ctx);
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    
    /* 生成密钥对 */
    if (kyber_keygen(ctx->public_key, ctx->secret_key) != 0) {
        OPENSSL_secure_clear_free(ctx->secret_key, ctx->secret_key_len);
        OPENSSL_secure_clear_free(ctx->public_key, ctx->public_key_len);
        OPENSSL_free(ctx);
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
        return NULL;
    }
    
    ctx->key_set = 1;
    return ctx;
}

static void kyber_freectx(void *vctx)
{
    KYBER_CTX *ctx = (KYBER_CTX *)vctx;
    if (ctx != NULL) {
        KYBER_PRINTF("Kyber KEM provider called: freectx\n");
        OPENSSL_secure_clear_free(ctx->secret_key, ctx->secret_key_len);
        OPENSSL_secure_clear_free(ctx->public_key, ctx->public_key_len);
        OPENSSL_clear_free(ctx, sizeof(*ctx));
    }
}

static int kyber_init(void *vctx, void *vkey, const OSSL_PARAM params[], int operation)
{
    KYBER_CTX *ctx = (KYBER_CTX *)vctx;

    KYBER_PRINTF3("Kyber KEM provider called: _init : New: %p; old: %p\n",
                  vkey, ctx->secret_key);
    if (ctx == NULL || vkey == NULL)
        return 0;

    /* 复制密钥 */
    memcpy(ctx->secret_key, vkey, ctx->secret_key_len);
    ctx->key_set = 1;

    return 1;
}

static int kyber_encapsulate_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    KYBER_PRINTF("Kyber KEM provider called: encaps_init\n");
    return kyber_init(vctx, vkey, params, EVP_PKEY_OP_ENCAPSULATE);
}

static int kyber_decapsulate_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    KYBER_PRINTF("Kyber KEM provider called: decaps_init\n");
    return kyber_init(vctx, vkey, params, EVP_PKEY_OP_DECAPSULATE);
}

static int kyber_encapsulate(void *vctx, unsigned char *out, size_t *outlen,
                            unsigned char *secret, size_t *secretlen)
{
    KYBER_CTX *ctx = (KYBER_CTX *)vctx;
    
    KYBER_PRINTF("Kyber KEM provider called: encaps\n");
    if (ctx == NULL || ctx->key_set == 0) {
        KYBER_PRINTF("Kyber Warning: KEM not initialized\n");
        return 0;
    }
    
    if (out == NULL || secret == NULL) {
        if (outlen != NULL)
            *outlen = ctx->ciphertext_len;
        if (secretlen != NULL)
            *secretlen = ctx->shared_secret_len;
        KYBER_PRINTF3("KEM returning lengths %ld and %ld\n",
                     ctx->ciphertext_len, ctx->shared_secret_len);
        return 1;
    }
    
    if (*outlen < ctx->ciphertext_len) {
        KYBER_PRINTF("Kyber Warning: out buffer too small\n");
        return 0;
    }
    if (*secretlen < ctx->shared_secret_len) {
        KYBER_PRINTF("Kyber Warning: secret buffer too small\n");
        return 0;
    }
    
    /* 生成随机数用于封装 */
    unsigned char seed[32];
    if (RAND_bytes(seed, sizeof(seed)) != 1) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
        return 0;
    }
    
    /* 调用实际的Kyber封装函数 */
    if (kyber_enc(seed, ctx->public_key, out, secret) != 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
        return 0;
    }
    
    *outlen = ctx->ciphertext_len;
    *secretlen = ctx->shared_secret_len;
    
    return 1;
}

static int kyber_decapsulate(void *vctx, unsigned char *out, size_t *outlen,
                            const unsigned char *in, size_t inlen)
{
    KYBER_CTX *ctx = (KYBER_CTX *)vctx;
    
    KYBER_PRINTF("Kyber KEM provider called: decaps\n");
    if (ctx == NULL || ctx->key_set == 0) {
        KYBER_PRINTF("Kyber Warning: KEM not initialized\n");
        return 0;
    }
    
    if (out == NULL) {
        if (outlen != NULL)
            *outlen = ctx->shared_secret_len;
        KYBER_PRINTF2("KEM returning length %ld\n", ctx->shared_secret_len);
        return 1;
    }
    
    if (inlen != ctx->ciphertext_len) {
        KYBER_PRINTF("Kyber Warning: wrong input length\n");
        return 0;
    }
    
    if (*outlen < ctx->shared_secret_len) {
        KYBER_PRINTF("Kyber Warning: out buffer too small\n");
        return 0;
    }
    
    /* 调用实际的Kyber解封装函数 */
    if (kyber_dec(in, ctx->secret_key, out) != 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
        return 0;
    }
    
    *outlen = ctx->shared_secret_len;
    
    return 1;
}

/* Kyber KEM 核心函数实现 */
static int kyber_keygen(unsigned char *pk, unsigned char *sk)
{
    /* 使用 pq-crystals/kyber 的密钥生成函数 */
    crypto_kem_keypair(pk, sk);
    return 0;  /* 成功返回0 */
}

static int kyber_enc(const unsigned char *seed, const unsigned char *pk,
                     unsigned char *ct, unsigned char *ss)
{
    /* 使用 pq-crystals/kyber 的封装函数 */
    crypto_kem_enc(ct, ss, pk);
    return 0;  /* 成功返回0 */
}

static int kyber_dec(const unsigned char *ct, const unsigned char *sk,
                     unsigned char *ss)
{
    /* 使用 pq-crystals/kyber 的解封装函数 */
    crypto_kem_dec(ss, ct, sk);
    return 0;  /* 成功返回0 */
}

const OSSL_DISPATCH kyber_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))kyber_newctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))kyber_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))kyber_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))kyber_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))kyber_decapsulate },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))kyber_freectx },
    { 0, NULL }
};
