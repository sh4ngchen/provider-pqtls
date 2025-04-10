#include <assert.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core.h>
#include <string.h>

/* For TLS1_VERSION etc */
#include <openssl/params.h>
#include <openssl/ssl.h>
#include <openssl/prov_ssl.h>

#include "../provider.h"

#if !defined(DTLS1_3_VERSION)
#define DTLS1_3_VERSION 0xFEFC
#endif

#define OSSL_NELEM(x) (sizeof(x) / sizeof((x)[0]))

typedef struct pq_group_constants_st {
    unsigned int group_id; /* Group ID */
    unsigned int secbits;  /* Bits of security */
    int mintls;            /* Minimum TLS version, -1 unsupported */
    int maxtls;            /* Maximum TLS version (or 0 for undefined) */
    int mindtls;           /* Minimum DTLS version, -1 unsupported */
    int maxdtls;           /* Maximum DTLS version (or 0 for undefined) */
    int is_kem;            /* Always set */
} PQ_GROUP_CONSTANTS;

typedef struct pq_sigalg_constants_st {
    unsigned int code_point; /* Code point */
    unsigned int secbits;    /* Bits of security */
    int mintls;              /* Minimum TLS version, -1 unsupported */
    int maxtls;              /* Maximum TLS version (or 0 for undefined) */
} PQ_SIGALG_CONSTANTS;

static PQ_GROUP_CONSTANTS pq_group_list[] = {
    {512, 128, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1},
    {513, 192, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1},
    {514, 256, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1},
};

#define PQ_GROUP_ENTRY(tlsname, realname, algorithm, idx)                     \
    {                                                                          \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME, #tlsname,       \
                               sizeof(#tlsname)),                              \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,    \
                                   #realname, sizeof(#realname)),              \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, #algorithm,  \
                                   sizeof(#algorithm)),                        \
            OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID,                      \
                            (unsigned int *)&pq_group_list[idx].group_id),    \
            OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,           \
                            (unsigned int *)&pq_group_list[idx].secbits),     \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS,                  \
                           (unsigned int *)&pq_group_list[idx].mintls),       \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS,                  \
                           (unsigned int *)&pq_group_list[idx].maxtls),       \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS,                 \
                           (unsigned int *)&pq_group_list[idx].mindtls),      \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS,                 \
                           (unsigned int *)&pq_group_list[idx].maxdtls),      \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_IS_KEM,                   \
                           (unsigned int *)&pq_group_list[idx].is_kem),       \
            OSSL_PARAM_END                                                     \
    }

static const OSSL_PARAM pq_param_group_list[][11] = {
    PQ_GROUP_ENTRY(kyber512, kyber512, kyber512, 0),
    PQ_GROUP_ENTRY(kyber768, kyber768, kyber768, 1),
    PQ_GROUP_ENTRY(kyber1024, kyber1024, kyber1024, 2),
};

static PQ_SIGALG_CONSTANTS pq_sigalg_list[] = {
    {0x0904, 128, TLS1_3_VERSION, 0},
    {0x0905, 192, TLS1_3_VERSION, 0},
    {0x0906, 256, TLS1_3_VERSION, 0},
};

#define PQ_SIGALG_ENTRY(tlsname, realname, algorithm, oid, idx)               \
    {                                                                          \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME, #tlsname, \
                               sizeof(#tlsname)),                              \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_NAME, #tlsname,  \
                                   sizeof(#tlsname)),                          \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_OID, #oid,       \
                                   sizeof(#oid)),                              \
            OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT,             \
                            (unsigned int *)&pq_sigalg_list[idx].code_point), \
            OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS,          \
                            (unsigned int *)&pq_sigalg_list[idx].secbits),    \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS,                 \
                           (unsigned int *)&pq_sigalg_list[idx].mintls),      \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS,                 \
                           (unsigned int *)&pq_sigalg_list[idx].maxtls),      \
            OSSL_PARAM_END                                                     \
    }

static const OSSL_PARAM pq_param_sigalg_list[][12] = {
    PQ_SIGALG_ENTRY(dilithium2, dilithium2, dilithium2, "1.3.6.1.4.1.2.267.7.4.4", 0),
    PQ_SIGALG_ENTRY(dilithium3, dilithium3, dilithium3, "1.3.6.1.4.1.2.267.7.6.5", 1),
    PQ_SIGALG_ENTRY(dilithium5, dilithium5, dilithium5, "1.3.6.1.4.1.2.267.7.8.7", 2)
};


static int pq_group_capability(OSSL_CALLBACK *cb, void *arg) {
    size_t i;

    for (i = 0; i < OSSL_NELEM(pq_group_list); i++) {
        if (!cb(pq_param_group_list[i], arg))
            return 0;
    }

    return 1;
}

static int pq_sigalg_capability(OSSL_CALLBACK *cb, void *arg) {
    size_t i;

    assert(OSSL_NELEM(pq_param_sigalg_list) <= OSSL_NELEM(pq_sigalg_list));
    for (i = 0; i < OSSL_NELEM(pq_param_sigalg_list); i++) {
        if (!cb(pq_param_sigalg_list[i], arg))
            return 0;
    }

    return 1;
}

int provider_get_capabilities(void *provctx, const char *capability,
                        OSSL_CALLBACK *cb, void *arg) {

    if (strcasecmp(capability, "TLS-GROUP") == 0)
        return pq_group_capability(cb, arg);
    
    if (strcasecmp(capability, "TLS-SIGALG") == 0)
        return pq_sigalg_capability(cb, arg);

    return 0;
}