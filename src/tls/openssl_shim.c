#include "openssl_shim.h"
#include <string.h>
#if OPENSSL_VERSION_MAJOR < 3
#error OpenSSL 3.x is required
#endif
static int no_password(char *buf, int size, int rwflag, void *arg) {
    (void)buf; (void)size; (void)rwflag; (void)arg;
    return 0;
}
static int http11(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                  const unsigned char *in, unsigned int len, void *arg) {
    (void)ssl; (void)arg;
    static const unsigned char protocol[] = "http/1.1";
    unsigned int i = 0;
    while (i < len) {
        unsigned int n = in[i++];
        if (n == 0 || n > len - i) return SSL_TLSEXT_ERR_ALERT_FATAL;
        if (n == sizeof(protocol)-1 && memcmp(in+i, protocol, n) == 0) {
            *out = protocol; *outlen = (unsigned char)n;
            return SSL_TLSEXT_ERR_OK;
        }
        i += n;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}
int zg_tls_policy(SSL_CTX *ctx) {
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) ||
        !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)) return 0;
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_TICKET);
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_default_passwd_cb(ctx, no_password);
    SSL_CTX_set_alpn_select_cb(ctx, http11, NULL);
    return SSL_CTX_set_max_early_data(ctx, 0) && SSL_CTX_set_num_tickets(ctx, 0);
}
void zg_tls_sni(SSL_CTX *ctx, int (*callback)(SSL *, int *, void *), void *arg) {
    SSL_CTX_set_tlsext_servername_callback(ctx, callback);
    SSL_CTX_set_tlsext_servername_arg(ctx, arg);
}
