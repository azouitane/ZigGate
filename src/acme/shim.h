#ifndef ZIGGATE_ACME_H
#define ZIGGATE_ACME_H
#include "openssl_shim.h"
#include <stdint.h>
#include <openssl/rand.h>
typedef struct {
    long status;
    size_t length, header_bytes;
    char nonce[512], location[2048], retry[128];
    unsigned char body[1048576];
} zg_acme_response;
int zg_acme_http_probe(void);
int zg_acme_http_init(void);
void zg_acme_http_cleanup(void);
int zg_acme_ca_pem(const unsigned char *bytes, int len);
int zg_acme_http(const char *url, int method, const unsigned char *body, size_t length,
                 const char *ca_file, zg_acme_response *response, const unsigned char *cancel);
EVP_PKEY *zg_acme_key_new(void);
EVP_PKEY *zg_acme_key_read(const unsigned char *bytes, int len);
int zg_acme_key_pem(EVP_PKEY *key, unsigned char *out, int cap);
int zg_acme_jwk(EVP_PKEY *key, char *out, int cap);
int zg_acme_thumb(EVP_PKEY *key, char *out, int cap);
int zg_acme_sign(EVP_PKEY *key, const unsigned char *bytes, size_t len, unsigned char *out);
int zg_acme_csr(EVP_PKEY *key, const char **domains, int count, unsigned char *out, int cap);
int zg_acme_validate(const unsigned char *chain, int len, EVP_PKEY *key, const char **domains,
                     int count, const char *ca, int allow_expired, int64_t *before, int64_t *after);
int zg_acme_cert_id(const unsigned char *chain, int len, char *out, int cap);
long long zg_acme_http_date(const char *text);
#endif
