/**
 * OpenSSL 3.0 Provider - Caesar Cipher 测试程序
 * 
 * 这个程序测试凯撒密码provider的功能。
 */

#include <stdio.h>
#include <string.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/**
 * 打印OpenSSL错误信息
 */
void print_error()
{
    char err_buf[256];
    unsigned long err = ERR_get_error();
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    fprintf(stderr, "错误: %s\n", err_buf);
}

int main(int argc, char *argv[])
{
    OSSL_PROVIDER *provider = NULL;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char key[1] = {3};  // 位移量为3
    const char *input = "Hello, World!";
    unsigned char output[1024];
    int outlen, tmplen;
    int ret = 1;

    // 加载provider
    provider = OSSL_PROVIDER_load(NULL, "/usr/local/lib64/ossl-modules/caesar.so");
    if (provider == NULL) {
        fprintf(stderr, "加载provider失败\n");
        print_error();
        goto cleanup;
    }

    // 获取CAESAR密码
    cipher = EVP_CIPHER_fetch(NULL, "CAESAR", "provider=caesar");
    if (cipher == NULL) {
        fprintf(stderr, "获取CAESAR密码失败\n");
        print_error();
        goto cleanup;
    }

    // 打印加密算法信息
    printf("密码算法信息:\n");
    printf("  名称: %s\n", EVP_CIPHER_get0_name(cipher));
    printf("  块大小: %d\n", EVP_CIPHER_get_block_size(cipher));
    printf("  密钥长度: %d\n", EVP_CIPHER_get_key_length(cipher));
    printf("  IV长度: %d\n", EVP_CIPHER_get_iv_length(cipher));

    // 创建cipher上下文
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "创建密码上下文失败\n");
        print_error();
        goto cleanup;
    }

    // 使用EVP API加密
    printf("\n使用EVP API加密:\n");
    memset(output, 0, sizeof(output));
    
    // 初始化上下文
    if (!EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL)) {
        fprintf(stderr, "初始化加密失败\n");
        print_error();
        goto cleanup;
    }
    
    // 加密数据
    if (!EVP_EncryptUpdate(ctx, output, &outlen, (unsigned char *)input, strlen(input))) {
        fprintf(stderr, "数据加密失败\n");
        print_error();
        goto cleanup;
    }
    
    // 完成加密
    if (!EVP_EncryptFinal_ex(ctx, output + outlen, &tmplen)) {
        fprintf(stderr, "完成加密失败\n");
        print_error();
        goto cleanup;
    }
    outlen += tmplen;
    output[outlen] = '\0'; // 确保字符串结束

    printf("加密结果:\n");
    printf("  输入: %s\n", input);
    printf("  输出: %s\n", output);
    printf("  输出长度: %d\n", outlen);

    ret = 0;

cleanup:
    // 清理资源
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (cipher) EVP_CIPHER_free(cipher);
    if (provider) OSSL_PROVIDER_unload(provider);
    return ret;
}