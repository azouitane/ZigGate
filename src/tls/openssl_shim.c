#include "openssl_shim.h"
#include <string.h>
#include <openssl/x509v3.h>
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

/* PEM decoding and all chain signature checks stay inside OpenSSL. Input bytes
 * have already been read from regular files with explicit size ceilings. */
static int skip_space(BIO *bio) {
    char *rest;
    long len;
    while ((len = BIO_get_mem_data(bio, &rest)) > 0) {
        if (*rest != ' ' && *rest != '\t' && *rest != '\r' && *rest != '\n') break;
        char ignored;
        if (BIO_read(bio, &ignored, 1) != 1) return -1;
    }
    return (int)len;
}
int zg_tls_certificate_pem(SSL_CTX *ctx, const unsigned char *bytes, int len) {
    BIO *bio = BIO_new_mem_buf(bytes, len);
    if (!bio) return 0;
    X509 *previous = NULL;
    int count = 0, ok = 0;
    while (skip_space(bio) > 0) {
        char *rest;
        long left = BIO_get_mem_data(bio, &rest);
        const char *marker = "-----BEGIN CERTIFICATE-----";
        const char *trusted = "-----BEGIN TRUSTED CERTIFICATE-----";
        if (!((left >= (long)strlen(marker) && memcmp(rest, marker, strlen(marker)) == 0) ||
              (left >= (long)strlen(trusted) && memcmp(rest, trusted, strlen(trusted)) == 0))) goto done;
        if (++count > 16) goto done;
        X509 *cert = PEM_read_bio_X509_AUX(bio, NULL, no_password, NULL);
        if (!cert) goto done;
        if (previous && (X509_check_issued(cert, previous) != X509_V_OK ||
                         X509_verify(previous, X509_get0_pubkey(cert)) != 1)) {
            X509_free(cert); goto done;
        }
        if (count == 1) {
            if (SSL_CTX_use_certificate(ctx, cert) != 1) { X509_free(cert); goto done; }
        } else {
            if (SSL_CTX_add1_chain_cert(ctx, cert) != 1) { X509_free(cert); goto done; }
        }
        X509_free(previous);
        previous = cert;
    }
    ok = count > 0;
done:
    X509_free(previous);
    BIO_free(bio);
    return ok;
}
int zg_tls_key_pem(SSL_CTX *ctx, const unsigned char *bytes, int len) {
    BIO *bio = BIO_new_mem_buf(bytes, len);
    if (!bio) return 0;
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, NULL, no_password, NULL);
    int ok = key && skip_space(bio) == 0 && SSL_CTX_use_PrivateKey(ctx, key) == 1;
    EVP_PKEY_free(key);
    BIO_free(bio);
    return ok;
}
