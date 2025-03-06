/**
 * OpenSSL 3.0 Provider - Kyber KEM Test
 * 
 * 这个文件测试Kyber密钥封装机制(KEM)的功能。
 */

#include <stdio.h>
#include <string.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#define PRINT_HEX(buf, len) do { \
    for (size_t i = 0; i < (len); i++) \
        printf("%02x", (unsigned char)(buf)[i]); \
    printf("\n"); \
} while (0)

int main(int argc, char **argv)
{
    OSSL_PROVIDER *defprov = NULL;
    OSSL_PROVIDER *pqtlsprov = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    unsigned char *secret1 = NULL;
    unsigned char *secret2 = NULL;
    size_t secret1_len = 0, secret2_len = 0;
    size_t params_len = 0;
    unsigned char *params_buf = NULL;
    int ret = 1;

    /* 加载provider */
    defprov = OSSL_PROVIDER_load(NULL, "default");
    if (defprov == NULL) {
        fprintf(stderr, "无法加载默认provider\n");
        goto end;
    }

    pqtlsprov = OSSL_PROVIDER_load(NULL, "pqtls");
    if (pqtlsprov == NULL) {
        fprintf(stderr, "无法加载pqtls provider\n");
        goto end;
    }

    /* 创建密钥生成上下文 */
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "KYBER", "provider=pqtls");
    if (pctx == NULL) {
        fprintf(stderr, "无法创建Kyber密钥生成上下文\n");
        goto end;
    }

    /* 初始化密钥生成 */
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        fprintf(stderr, "无法初始化Kyber密钥生成\n");
        goto end;
    }

    /* 生成密钥对 */
    if (EVP_PKEY_generate(pctx, &pkey) <= 0) {
        fprintf(stderr, "无法生成Kyber密钥对\n");
        goto end;
    }

    printf("成功生成Kyber密钥对\n");

    /* 导出公钥参数 */
    kctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (kctx == NULL) {
        fprintf(stderr, "无法创建密钥操作上下文\n");
        goto end;
    }

    /* 初始化密钥派生（用于封装） */
    if (EVP_PKEY_derive_init(kctx) <= 0) {
        fprintf(stderr, "无法初始化密钥派生\n");
        goto end;
    }

    /* 获取参数长度 */
    if (EVP_PKEY_CTX_get_params(kctx, NULL, &params_len) <= 0) {
        fprintf(stderr, "无法获取参数长度\n");
        goto end;
    }

    params_buf = OPENSSL_malloc(params_len);
    if (params_buf == NULL) {
        fprintf(stderr, "内存分配失败\n");
        goto end;
    }

    /* 获取参数 */
    if (EVP_PKEY_CTX_get_params(kctx, params_buf, &params_len) <= 0) {
        fprintf(stderr, "无法获取参数\n");
        goto end;
    }

    printf("Kyber参数长度: %zu\n", params_len);
    printf("Kyber参数: ");
    PRINT_HEX(params_buf, params_len);

    /* 派生共享密钥 */
    if (EVP_PKEY_derive(kctx, NULL, &secret1_len) <= 0) {
        fprintf(stderr, "无法获取共享密钥长度\n");
        goto end;
    }

    secret1 = OPENSSL_malloc(secret1_len);
    if (secret1 == NULL) {
        fprintf(stderr, "内存分配失败\n");
        goto end;
    }

    if (EVP_PKEY_derive(kctx, secret1, &secret1_len) <= 0) {
        fprintf(stderr, "无法派生共享密钥\n");
        goto end;
    }

    printf("共享密钥1长度: %zu\n", secret1_len);
    printf("共享密钥1: ");
    PRINT_HEX(secret1, secret1_len);

    /* 使用相同的参数再次派生共享密钥 */
    EVP_PKEY_CTX_free(kctx);
    kctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (kctx == NULL) {
        fprintf(stderr, "无法创建密钥操作上下文\n");
        goto end;
    }

    if (EVP_PKEY_derive_init(kctx) <= 0) {
        fprintf(stderr, "无法初始化密钥派生\n");
        goto end;
    }

    if (EVP_PKEY_CTX_set_params(kctx, params_buf, params_len) <= 0) {
        fprintf(stderr, "无法设置参数\n");
        goto end;
    }

    if (EVP_PKEY_derive(kctx, NULL, &secret2_len) <= 0) {
        fprintf(stderr, "无法获取共享密钥长度\n");
        goto end;
    }

    secret2 = OPENSSL_malloc(secret2_len);
    if (secret2 == NULL) {
        fprintf(stderr, "内存分配失败\n");
        goto end;
    }

    if (EVP_PKEY_derive(kctx, secret2, &secret2_len) <= 0) {
        fprintf(stderr, "无法派生共享密钥\n");
        goto end;
    }

    printf("共享密钥2长度: %zu\n", secret2_len);
    printf("共享密钥2: ");
    PRINT_HEX(secret2, secret2_len);

    /* 验证两个共享密钥是否相同 */
    if (secret1_len == secret2_len && memcmp(secret1, secret2, secret1_len) == 0) {
        printf("测试成功: 两个共享密钥相同\n");
        ret = 0;
    } else {
        printf("测试失败: 两个共享密钥不同\n");
    }

end:
    /* 清理资源 */
    OPENSSL_free(secret1);
    OPENSSL_free(secret2);
    OPENSSL_free(params_buf);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    OSSL_PROVIDER_unload(pqtlsprov);
    OSSL_PROVIDER_unload(defprov);

    return ret;
}
