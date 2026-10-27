#ifndef ZIGGATE_OPENSSL_SHIM_H
#define ZIGGATE_OPENSSL_SHIM_H
#define OPENSSL_API_COMPAT 30000
#define OPENSSL_NO_DEPRECATED
#include <openssl/ssl.h>
#include <openssl/err.h>
int zg_tls_policy(SSL_CTX *ctx);
void zg_tls_sni(SSL_CTX *ctx, int (*callback)(SSL *, int *, void *), void *arg);
#endif
