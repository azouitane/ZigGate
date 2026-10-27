#define _GNU_SOURCE
#include "shim.h"
#include <curl/curl.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/x509v3.h>
#include <dlfcn.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <limits.h>
#include <time.h>

/* Dynamic loading keeps HTTP/manual TLS independent of a libcurl installation.
 * Official headers define the stable ABI; no hand-copied option constants. */
static CURLcode (*p_global_init)(long);
static void (*p_global_cleanup)(void);
static int http_initialized;
static curl_version_info_data *(*p_version)(CURLversion);
static CURL *(*p_init)(void);
static void (*p_cleanup)(CURL *);
static CURLcode (*p_setopt)(CURL *, CURLoption, ...);
static CURLcode (*p_perform)(CURL *);
static CURLcode (*p_getinfo)(CURL *, CURLINFO, ...);
static struct curl_slist *(*p_append)(struct curl_slist *, const char *);
static void (*p_free_list)(struct curl_slist *);
static time_t (*p_getdate)(const char *, const time_t *);
int zg_acme_http_probe(void) {
    static int available;
    if (available) return 1;
    void *lib = dlopen("libcurl.so.4", RTLD_NOW | RTLD_LOCAL);
    if (!lib) return 0;
#define LOAD(name, symbol) do { void *sym = dlsym(lib, symbol); if (!sym) return 0; memcpy(&name, &sym, sizeof(name)); } while(0)
    LOAD(p_global_cleanup, "curl_global_cleanup");
    LOAD(p_global_init, "curl_global_init"); LOAD(p_version, "curl_version_info");
    LOAD(p_cleanup, "curl_easy_cleanup"); LOAD(p_setopt, "curl_easy_setopt");
    LOAD(p_perform, "curl_easy_perform"); LOAD(p_getinfo, "curl_easy_getinfo");
    LOAD(p_append, "curl_slist_append"); LOAD(p_free_list, "curl_slist_free_all");
    LOAD(p_getdate, "curl_getdate");
    curl_version_info_data *v = p_version(CURLVERSION_NOW);
    if (!v || v->version_num < 0x075500 || !(v->features & CURL_VERSION_THREADSAFE) || !v->ssl_version || !strstr(v->ssl_version, "OpenSSL/") || !(v->features & CURL_VERSION_ASYNCHDNS)) return 0;
    LOAD(p_init, "curl_easy_init");
    available=1;
#undef LOAD
    /* One process-lifetime handle: do not unload underneath resolver internals. */
    return 1;
}
int zg_acme_http_init(void) {
    if (http_initialized) return 1;
    if (!zg_acme_http_probe() || p_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) return 0;
    http_initialized=1;
    return 1;
}
void zg_acme_http_cleanup(void) { if (http_initialized) { p_global_cleanup(); http_initialized=0; } }
int zg_acme_ca_pem(const unsigned char *bytes, int len) {
    BIO *bio=BIO_new_mem_buf(bytes,len); if (!bio) return 0;
    X509 *cert=PEM_read_bio_X509_AUX(bio,NULL,NULL,NULL);
    int valid=cert!=NULL; X509_free(cert); BIO_free(bio); ERR_clear_error(); return valid;
}
static size_t receive_body(char *data, size_t size, size_t count, void *arg) {
    zg_acme_response *r = arg;
    if (size && count > SIZE_MAX / size) return 0;
    size_t n = size * count;
    if (n > sizeof(r->body) - r->length) return 0;
    memcpy(r->body + r->length, data, n); r->length += n;
    return n;
}
static int header_value(char *destination, size_t cap, const char *data, size_t n) {
    while (n && (*data == ' ' || *data == '\t')) { ++data; --n; }
    while (n && (data[n-1] == '\r' || data[n-1] == '\n' || data[n-1] == ' ')) --n;
    if (!n || n >= cap || destination[0]) return 0;
    for (size_t i=0; i<n; ++i) if ((unsigned char)data[i] < 0x20 || (unsigned char)data[i] >= 0x7f) return 0;
    memcpy(destination, data, n); destination[n] = 0;
    return 1;
}
static size_t receive_header(char *data, size_t size, size_t count, void *arg) {
    zg_acme_response *r = arg;
    if (size && count > SIZE_MAX / size) return 0;
    size_t n = size * count;
    if (n > 16384 - r->header_bytes) return 0;
    r->header_bytes += n;
#define HEADER(name, field) if (n > sizeof(name)-1 && strncasecmp(data, name, sizeof(name)-1) == 0) { if (!header_value(r->field, sizeof(r->field), data+sizeof(name)-1, n-(sizeof(name)-1))) return 0; }
    HEADER("Replay-Nonce:", nonce)
    HEADER("Location:", location)
    HEADER("Retry-After:", retry)
#undef HEADER
    return n;
}
static int progress(void *arg, curl_off_t a, curl_off_t b, curl_off_t c, curl_off_t d) {
    (void)a; (void)b; (void)c; (void)d;
    return __atomic_load_n((const unsigned char *)arg, __ATOMIC_RELAXED) != 0;
}
int zg_acme_http(const char *url, int method, const unsigned char *body, size_t length,
                 const char *ca_file, zg_acme_response *response, const unsigned char *cancel) {
    memset(response, 0, sizeof(*response));
    CURL *curl = p_init(); if (!curl) return 0;
    struct curl_slist *headers = NULL;
    int ok = 0;
#define SET(option, value) do { if (p_setopt(curl, option, value) != CURLE_OK) goto done; } while(0)
    SET(CURLOPT_URL, url); SET(CURLOPT_PROTOCOLS_STR, "https"); SET(CURLOPT_REDIR_PROTOCOLS_STR, "https");
    SET(CURLOPT_FOLLOWLOCATION, 0L); SET(CURLOPT_PATH_AS_IS, 1L); SET(CURLOPT_PROXY, ""); SET(CURLOPT_NETRC, (long)CURL_NETRC_IGNORED);
    SET(CURLOPT_SSL_VERIFYPEER, 1L); SET(CURLOPT_SSL_VERIFYHOST, 2L);
    SET(CURLOPT_SSLVERSION, (long)CURL_SSLVERSION_TLSv1_2);
    SET(CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_1_1);
    SET(CURLOPT_CONNECTTIMEOUT_MS, 5000L); SET(CURLOPT_TIMEOUT_MS, 15000L); SET(CURLOPT_NOSIGNAL, 1L);
    SET(CURLOPT_NOPROGRESS, 0L); SET(CURLOPT_XFERINFOFUNCTION, progress); SET(CURLOPT_XFERINFODATA, (void *)cancel);
    SET(CURLOPT_WRITEFUNCTION, receive_body); SET(CURLOPT_WRITEDATA, (void *)response);
    SET(CURLOPT_HEADERFUNCTION, receive_header); SET(CURLOPT_HEADERDATA, (void *)response);
    SET(CURLOPT_USERAGENT, "ZigGate-ACME/1");
    if (ca_file && *ca_file) SET(CURLOPT_CAINFO, ca_file);
    if (method == 1) SET(CURLOPT_NOBODY, 1L);
    if (method == 2) {
        headers = p_append(NULL, "Content-Type: application/jose+json"); if (!headers) goto done;
        struct curl_slist *next = p_append(headers, "Expect:"); if (!next) goto done; headers = next;
        SET(CURLOPT_HTTPHEADER, headers); SET(CURLOPT_POSTFIELDS, (const char *)body); SET(CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)length);
    }
    if (p_perform(curl) != CURLE_OK) goto done;
    if (p_getinfo(curl, CURLINFO_RESPONSE_CODE, &response->status) != CURLE_OK) goto done;
    ok = 1;
done:
    p_free_list(headers); p_cleanup(curl);
#undef SET
    return ok;
}
long long zg_acme_http_date(const char *text) { return p_getdate ? (long long)p_getdate(text, NULL) : -1; }
static int no_password(char *buf, int len, int flag, void *arg) { (void)buf; (void)len; (void)flag; (void)arg; return 0; }
EVP_PKEY *zg_acme_key_new(void) { return EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1"); }
EVP_PKEY *zg_acme_key_read(const unsigned char *bytes, int len) {
    BIO *bio = BIO_new_mem_buf(bytes, len); if (!bio) return NULL;
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, NULL, no_password, NULL); BIO_free(bio);
    char group[64]; size_t used;
    if (key && (!EVP_PKEY_is_a(key, "EC") || !EVP_PKEY_get_group_name(key, group, sizeof(group), &used) || strcmp(group, "prime256v1"))) { EVP_PKEY_free(key); key = NULL; }
    return key;
}
int zg_acme_key_pem(EVP_PKEY *key, unsigned char *out, int cap) {
    BIO *bio = BIO_new(BIO_s_secmem()); if (!bio) return 0;
    int n=0; char *data;
    if (PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL) == 1) {
        long len = BIO_get_mem_data(bio, &data);
        if (len > 0 && len <= cap) { memcpy(out, data, (size_t)len); n=(int)len; }
    }
    BIO_free(bio); return n;
}
static int b64url(const unsigned char *data, int len, char *out, int cap) {
    int needed = 4 * ((len+2)/3); if (cap <= needed) return 0;
    EVP_EncodeBlock((unsigned char *)out, data, len);
    while (needed && out[needed-1] == '=') --needed;
    for (int i=0; i<needed; ++i) { if (out[i] == '+') out[i]='-'; if (out[i] == '/') out[i]='_'; }
    out[needed]=0; return needed;
}
int zg_acme_jwk(EVP_PKEY *key, char *out, int cap) {
    unsigned char point[65]; size_t len=0; char x[48], y[48];
    if (!EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, point, sizeof(point), &len) || len != 65 || point[0] != 4) return 0;
    if (!b64url(point+1, 32, x, sizeof(x)) || !b64url(point+33, 32, y, sizeof(y))) return 0;
    int n=snprintf(out, (size_t)cap, "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}", x, y);
    return n>0 && n<cap ? n : 0;
}
int zg_acme_thumb(EVP_PKEY *key, char *out, int cap) {
    char jwk[256]; unsigned char digest[32]; size_t len;
    int n=zg_acme_jwk(key, jwk, sizeof(jwk));
    if (!n || !EVP_Q_digest(NULL, "SHA256", NULL, jwk, (size_t)n, digest, &len) || len != 32) return 0;
    return b64url(digest, 32, out, cap);
}
int zg_acme_sign(EVP_PKEY *key, const unsigned char *bytes, size_t len, unsigned char *out) {
    EVP_MD_CTX *ctx=EVP_MD_CTX_new(); if (!ctx) return 0;
    unsigned char der[128]; size_t used=sizeof(der); int ok=0;
    if (EVP_DigestSignInit_ex(ctx, NULL, "SHA256", NULL, NULL, key, NULL) != 1 || EVP_DigestSign(ctx, der, &used, bytes, len) != 1) goto done;
    const unsigned char *cursor=der;
    ECDSA_SIG *sig=d2i_ECDSA_SIG(NULL, &cursor, (long)used); if (!sig) goto done;
    const BIGNUM *r,*s; ECDSA_SIG_get0(sig,&r,&s);
    ok=BN_bn2binpad(r,out,32)==32 && BN_bn2binpad(s,out+32,32)==32;
    ECDSA_SIG_free(sig);
done: EVP_MD_CTX_free(ctx); return ok;
}
int zg_acme_csr(EVP_PKEY *key, const char **domains, int count, unsigned char *out, int cap) {
    if (count<1 || count>8) return 0;
    X509_REQ *req=X509_REQ_new(); GENERAL_NAMES *names=sk_GENERAL_NAME_new_null();
    STACK_OF(X509_EXTENSION) *exts=sk_X509_EXTENSION_new_null(); int len=0;
    if (!req || !names || !exts || X509_REQ_set_version(req,0)!=1 || X509_REQ_set_pubkey(req,key)!=1) goto done;
    for (int i=0;i<count;++i) {
        GENERAL_NAME *name=GENERAL_NAME_new(); ASN1_IA5STRING *dns=ASN1_IA5STRING_new();
        if (!name || !dns || ASN1_STRING_set(dns,domains[i],(int)strlen(domains[i]))!=1) { GENERAL_NAME_free(name); ASN1_IA5STRING_free(dns); goto done; }
        GENERAL_NAME_set0_value(name,GEN_DNS,dns);
        if (!sk_GENERAL_NAME_push(names,name)) { GENERAL_NAME_free(name); goto done; }
    }
    X509_EXTENSION *ext=X509V3_EXT_i2d(NID_subject_alt_name,1,names);
    if (!ext) goto done;
    if (!sk_X509_EXTENSION_push(exts,ext)) { X509_EXTENSION_free(ext); goto done; }
    if (X509_REQ_add_extensions(req,exts)!=1 || X509_REQ_sign(req,key,EVP_sha256())<=0) goto done;
    int needed=i2d_X509_REQ(req,NULL); if (needed<=0 || needed>cap) goto done;
    unsigned char *cursor=out; len=i2d_X509_REQ(req,&cursor);
done: X509_REQ_free(req); GENERAL_NAMES_free(names); sk_X509_EXTENSION_pop_free(exts,X509_EXTENSION_free); return len;
}
int zg_acme_validate(const unsigned char *chain, int len, EVP_PKEY *key, const char **domains,
                     int count, const char *ca, int allow_expired, int64_t *before, int64_t *after) {
    SSL_CTX *ctx=SSL_CTX_new(TLS_server_method()); X509_STORE *store=NULL; X509_STORE_CTX *verify=NULL;
    int ok=0; GENERAL_NAMES *names=NULL;
    if (!ctx || !zg_tls_certificate_pem(ctx,chain,len) || SSL_CTX_use_PrivateKey(ctx,key)!=1 || SSL_CTX_check_private_key(ctx)!=1) goto done;
    X509 *leaf=SSL_CTX_get0_certificate(ctx);
    struct tm tm_before,tm_after;
    if (!ASN1_TIME_to_tm(X509_get0_notBefore(leaf),&tm_before) || !ASN1_TIME_to_tm(X509_get0_notAfter(leaf),&tm_after)) goto done;
    *before=(int64_t)timegm(&tm_before); *after=(int64_t)timegm(&tm_after);
    if ((!allow_expired && *after <= (int64_t)time(NULL)+60) || *after <= *before || *after-*before>398LL*86400) goto done;
    names=X509_get_ext_d2i(leaf,NID_subject_alt_name,NULL,NULL);
    if (!names || sk_GENERAL_NAME_num(names)!=count) goto done;
    for (int i=0;i<count;++i) {
        int found=0;
        for (int j=0;j<count;++j) {
            GENERAL_NAME *name=sk_GENERAL_NAME_value(names,j);
            if (name->type!=GEN_DNS) goto done;
            const unsigned char *text=ASN1_STRING_get0_data(name->d.dNSName);
            int length=ASN1_STRING_length(name->d.dNSName);
            if (length==(int)strlen(domains[i]) && strncasecmp((const char *)text,domains[i],(size_t)length)==0) ++found;
        }
        if (found!=1) goto done;
    }
    store=X509_STORE_new(); verify=X509_STORE_CTX_new(); if (!store || !verify) goto done;
    if (X509_STORE_set_default_paths(store)!=1 || X509_STORE_set_flags(store, X509_V_FLAG_X509_STRICT | X509_V_FLAG_TRUSTED_FIRST)!=1) goto done;
    if (ca && *ca && X509_STORE_load_file(store,ca)!=1) goto done;
    STACK_OF(X509) *intermediates=NULL; SSL_CTX_get0_chain_certs(ctx,&intermediates);
    if (allow_expired && X509_STORE_set_flags(store, X509_V_FLAG_NO_CHECK_TIME)!=1) goto done;
    if (X509_STORE_CTX_init(verify,store,leaf,intermediates)!=1 || X509_STORE_CTX_set_purpose(verify,X509_PURPOSE_SSL_SERVER)!=1) goto done;
    X509_VERIFY_PARAM_set_auth_level(X509_STORE_CTX_get0_param(verify),2);
    if (X509_verify_cert(verify)!=1) goto done;
    for (int i=0; intermediates && i<sk_X509_num(intermediates); ++i) {
        X509 *cert=sk_X509_value(intermediates,i);
        struct tm start,end;
        if (!ASN1_TIME_to_tm(X509_get0_notBefore(cert),&start) || !ASN1_TIME_to_tm(X509_get0_notAfter(cert),&end)) goto done;
        int64_t first=(int64_t)timegm(&start), last=(int64_t)timegm(&end);
        if (first>*before) *before=first;
        if (last<*after) *after=last;
    }
    if (*after<=*before || (!allow_expired && *after <= (int64_t)time(NULL)+60)) goto done;
    ok=1;
done: GENERAL_NAMES_free(names); X509_STORE_CTX_free(verify); X509_STORE_free(store); SSL_CTX_free(ctx); ERR_clear_error(); return ok;
}

int zg_acme_cert_id(const unsigned char *chain, int len, char *out, int cap) {
    BIO *bio=BIO_new_mem_buf(chain,len); if (!bio) return 0;
    X509 *leaf=PEM_read_bio_X509(bio,NULL,NULL,NULL); BIO_free(bio); if (!leaf) return 0;
    AUTHORITY_KEYID *aki=X509_get_ext_d2i(leaf,NID_authority_key_identifier,NULL,NULL);
    unsigned char serial[64], *cursor=serial; char a[512], b[128]; int result=0;
    if (!aki || !aki->keyid || ASN1_STRING_length(aki->keyid)>256) goto done;
    int n=i2d_ASN1_INTEGER(X509_get0_serialNumber(leaf),NULL);
    if (n<3 || n>(int)sizeof(serial) || i2d_ASN1_INTEGER(X509_get0_serialNumber(leaf),&cursor)!=n || serial[0]!=2 || serial[1]>=128 || serial[1]+2!=n) goto done;
    if (!b64url(ASN1_STRING_get0_data(aki->keyid),ASN1_STRING_length(aki->keyid),a,sizeof(a)) || !b64url(serial+2,n-2,b,sizeof(b))) goto done;
    n=snprintf(out,(size_t)cap,"%s.%s",a,b); if (n>0 && n<cap) result=n;
done: AUTHORITY_KEYID_free(aki); X509_free(leaf); return result;
}
