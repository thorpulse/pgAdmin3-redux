/* Copyright (C) 2009, 2010 Simon Josefsson
 * Copyright (C) 2006, 2007 The Written Word, Inc.  All rights reserved.
 * Copyright (c) 2004-2006, Sara Golemon <sarag@libssh2.org>
 *
 * Author: Simon Josefsson
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#include "libssh2_priv.h"

#ifdef LIBSSH2_OPENSSL /* compile only if we build with openssl */

#include <string.h>

#ifndef EVP_MAX_BLOCK_LENGTH
#define EVP_MAX_BLOCK_LENGTH 32
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static void *
OPENSSL_zalloc(size_t num)
{
    void *ret = OPENSSL_malloc(num);

    if (ret != NULL)
        memset(ret, 0, num);
    return ret;
}

HMAC_CTX *
HMAC_CTX_new(void)
{   
    HMAC_CTX *ctx = OPENSSL_zalloc(sizeof(HMAC_CTX));
    
    if (ctx != NULL) {
        HMAC_CTX_init(ctx);
    }
    return ctx;
}

void
HMAC_CTX_free(HMAC_CTX *ctx)
{
    if (ctx != NULL) {
        HMAC_CTX_cleanup(ctx);
        OPENSSL_free(ctx);
    }
}

static EVP_MD_CTX *
EVP_MD_CTX_new(void)
{
    return EVP_MD_CTX_create();
}

static void
EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
    EVP_MD_CTX_destroy(ctx);
}

static void
RSA_get0_key(const RSA *r,
             const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n != NULL)
        *n = r->n;
    if (e != NULL)
        *e = r->e;
    if (d != NULL)
        *d = r->d;
}

static int
RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    /* If the fields n and e in r are NULL, the corresponding input
     * parameters MUST be non-NULL for n and e.  d may be
     * left NULL (in case only the public key is used).
     */
    if ((r->n == NULL && n == NULL)
        || (r->e == NULL && e == NULL))
        return 0;

    if (n != NULL) {
        BN_free(r->n);
        r->n = n;
    }
    if (e != NULL) {
        BN_free(r->e);
        r->e = e;
    }
    if (d != NULL) {
        BN_free(r->d);
        r->d = d;
    }

    return 1;
}

static int
RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q)
{
    /* If the fields p and q in r are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((r->p == NULL && p == NULL)
        || (r->q == NULL && q == NULL))
        return 0;

    if (p != NULL) {
        BN_free(r->p);
        r->p = p;
    }
    if (q != NULL) {
        BN_free(r->q);
        r->q = q;
    }

    return 1;
}

static int
RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
    /* If the fields dmp1, dmq1 and iqmp in r are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((r->dmp1 == NULL && dmp1 == NULL)
        || (r->dmq1 == NULL && dmq1 == NULL)
        || (r->iqmp == NULL && iqmp == NULL))
        return 0;

    if (dmp1 != NULL) {
        BN_free(r->dmp1);
        r->dmp1 = dmp1;
    }
    if (dmq1 != NULL) {
        BN_free(r->dmq1);
        r->dmq1 = dmq1;
    }
    if (iqmp != NULL) {
        BN_free(r->iqmp);
        r->iqmp = iqmp;
    }

    return 1;
}

static void
DSA_get0_pqg(const DSA *d,
             const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
    if (p != NULL)
        *p = d->p;
    if (q != NULL)
        *q = d->q;
    if (g != NULL)
        *g = d->g;
}

static int
DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    /* If the fields p, q and g in d are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((d->p == NULL && p == NULL)
        || (d->q == NULL && q == NULL)
        || (d->g == NULL && g == NULL))
        return 0;

    if (p != NULL) {
        BN_free(d->p);
        d->p = p;
    }
    if (q != NULL) {
        BN_free(d->q);
        d->q = q;
    }
    if (g != NULL) {
        BN_free(d->g);
        d->g = g;
    }

    return 1;
}

static void
DSA_get0_key(const DSA *d,
             const BIGNUM **pub_key, const BIGNUM **priv_key)
{
    if (pub_key != NULL)
        *pub_key = d->pub_key;
    if (priv_key != NULL)
        *priv_key = d->priv_key;
}

static int
DSA_set0_key(DSA *d, BIGNUM *pub_key, BIGNUM *priv_key)
{
    /* If the field pub_key in d is NULL, the corresponding input
     * parameters MUST be non-NULL.  The priv_key field may
     * be left NULL.
     */
    if (d->pub_key == NULL && pub_key == NULL)
        return 0;

    if (pub_key != NULL) {
        BN_free(d->pub_key);
        d->pub_key = pub_key;
    }
    if (priv_key != NULL) {
        BN_free(d->priv_key);
        d->priv_key = priv_key;
    }

    return 1;
}

static int
DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    if (r == NULL || s == NULL)
        return 0;
    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    sig->r = r;
    sig->s = s;
    return 1;
}

static void
DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
    if (pr != NULL)
        *pr = sig->r;
    if (ps != NULL)
        *ps = sig->s;
}

static EVP_CIPHER *
EVP_CIPHER_meth_new(int cipher_type, int block_size, int key_len)
{
    EVP_CIPHER *cipher = OPENSSL_zalloc(sizeof(EVP_CIPHER));

    if (cipher != NULL) {
        cipher->nid = cipher_type;
        cipher->block_size = block_size;
        cipher->key_len = key_len;
    }
    return cipher;
}

static int
EVP_CIPHER_meth_set_iv_length(EVP_CIPHER *cipher, int iv_len)
{
    cipher->iv_len = iv_len;
    return 1;
}

static int
EVP_CIPHER_meth_set_init(EVP_CIPHER *cipher,
                         int (*init) (EVP_CIPHER_CTX *ctx,
                                      const unsigned char *key,
                                      const unsigned char *iv,
                                      int enc))
{
    cipher->init = init;
    return 1;
}

static int
EVP_CIPHER_meth_set_do_cipher(EVP_CIPHER *cipher,
                              int (*do_cipher) (EVP_CIPHER_CTX *ctx,
                                                unsigned char *out,
                                                const unsigned char *in,
                                                size_t inl))
{
    cipher->do_cipher = do_cipher;
    return 1;
}

static int
EVP_CIPHER_meth_set_cleanup(EVP_CIPHER *cipher,
                            int (*cleanup) (EVP_CIPHER_CTX *))
{
    cipher->cleanup = cleanup;
    return 1;
}
#endif

int
_libssh2_rsa_new(libssh2_rsa_ctx ** rsa,
                 const unsigned char *edata,
                 unsigned long elen,
                 const unsigned char *ndata,
                 unsigned long nlen,
                 const unsigned char *ddata,
                 unsigned long dlen,
                 const unsigned char *pdata,
                 unsigned long plen,
                 const unsigned char *qdata,
                 unsigned long qlen,
                 const unsigned char *e1data,
                 unsigned long e1len,
                 const unsigned char *e2data,
                 unsigned long e2len,
                 const unsigned char *coeffdata, unsigned long coefflen)
{
    *rsa = RSA_new();
    BIGNUM *e, *n;

    e = BN_new();
    BN_bin2bn(edata, elen, e);

    n = BN_new();
    BN_bin2bn(ndata, nlen, n);

    RSA_set0_key(*rsa, n, e, NULL);

    if (ddata) {
        BIGNUM *d;
        BIGNUM *p, *q, *dmp1, *dmq1, *iqmp;

        d = BN_new();
        BN_bin2bn(ddata, dlen, d);

        RSA_set0_key(*rsa, 0, 0, d);

        p = BN_new();
        BN_bin2bn(pdata, plen, p);

        q = BN_new();
        BN_bin2bn(qdata, qlen, q);

        RSA_set0_factors(*rsa, p, q);

        dmp1 = BN_new();
        BN_bin2bn(e1data, e1len, dmp1);

        dmq1 = BN_new();
        BN_bin2bn(e2data, e2len, dmq1);

        iqmp = BN_new();
        BN_bin2bn(coeffdata, coefflen, iqmp);

        RSA_set0_crt_params(*rsa, dmp1, dmq1, iqmp);
    }
    return 0;
}

int
_libssh2_rsa_sha1_verify(libssh2_rsa_ctx * rsactx,
                         const unsigned char *sig,
                         unsigned long sig_len,
                         const unsigned char *m, unsigned long m_len)
{
    unsigned char hash[SHA_DIGEST_LENGTH];
    int ret;

    if (_libssh2_sha1(m, m_len, hash))
        return -1; /* failure */
    ret = RSA_verify(NID_sha1, hash, SHA_DIGEST_LENGTH,
                     (unsigned char *) sig, sig_len, rsactx);
    return (ret == 1) ? 0 : -1;
}

#if LIBSSH2_DSA
int
_libssh2_dsa_new(libssh2_dsa_ctx ** dsactx,
                 const unsigned char *p,
                 unsigned long p_len,
                 const unsigned char *q,
                 unsigned long q_len,
                 const unsigned char *g,
                 unsigned long g_len,
                 const unsigned char *y,
                 unsigned long y_len,
                 const unsigned char *x, unsigned long x_len)
{
    BIGNUM *pn, *qn, *gn;
    BIGNUM *pub_key, *priv_key;

    *dsactx = DSA_new();

    pn = BN_new();
    BN_bin2bn(p, p_len, pn);

    qn = BN_new();
    BN_bin2bn(q, q_len, qn);

    gn = BN_new();
    BN_bin2bn(g, g_len, gn);

    DSA_set0_pqg(*dsactx, pn, qn, gn);

    pub_key = BN_new();
    BN_bin2bn(y, y_len, pub_key);

    if (x_len) {
        priv_key = BN_new();
        BN_bin2bn(x, x_len, priv_key);
    } else {
        priv_key = NULL;
    }

    DSA_set0_key(*dsactx, pub_key, priv_key);

    return 0;
}

int
_libssh2_dsa_sha1_verify(libssh2_dsa_ctx * dsactx,
                         const unsigned char *sig,
                         const unsigned char *m, unsigned long m_len)
{
    unsigned char hash[SHA_DIGEST_LENGTH];
    DSA_SIG *dsasig;
    BIGNUM *r, *s;
    int ret = -1;

    dsasig = DSA_SIG_new();
    r = BN_new();
    BN_bin2bn(sig, 20, r);
    s = BN_new();
    BN_bin2bn(sig + 20, 20, s);
    DSA_SIG_set0(dsasig, r, s);

    if (!_libssh2_sha1(m, m_len, hash))
        /* _libssh2_sha1() succeeded */
        ret = DSA_do_verify(hash, SHA_DIGEST_LENGTH, dsasig, dsactx);

    DSA_SIG_free(dsasig);

    return (ret == 1) ? 0 : -1;
}
#endif /* LIBSSH_DSA */

int
_libssh2_cipher_init(_libssh2_cipher_ctx * h,
                     _libssh2_cipher_type(algo),
                     unsigned char *iv, unsigned char *secret, int encrypt)
{
    *h = EVP_CIPHER_CTX_new();
    return !EVP_CipherInit(*h, algo(), secret, iv, encrypt);
}

int
_libssh2_cipher_crypt(_libssh2_cipher_ctx * ctx,
                      _libssh2_cipher_type(algo),
                      int encrypt, unsigned char *block, size_t blocksize)
{
    unsigned char buf[EVP_MAX_BLOCK_LENGTH];
    int ret;
    (void) algo;
    (void) encrypt;

    ret = EVP_Cipher(*ctx, buf, block, blocksize);
    if (ret == 1) {
        memcpy(block, buf, blocksize);
    }
    return ret == 1 ? 0 : 1;
}

#if LIBSSH2_AES_CTR

#include <openssl/aes.h>
#include <openssl/evp.h>

typedef struct
{
    AES_KEY       key;
    EVP_CIPHER_CTX *aes_ctx;
    unsigned char ctr[AES_BLOCK_SIZE];
} aes_ctr_ctx;

static int
aes_ctr_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
             const unsigned char *iv, int enc) /* init key */
{
    /*
     * variable "c" is leaked from this scope, but is later freed
     * in aes_ctr_cleanup
     */
    aes_ctr_ctx *c;
    const EVP_CIPHER *aes_cipher;
    (void) enc;

    switch (EVP_CIPHER_CTX_key_length(ctx)) {
    case 16:
        aes_cipher = EVP_aes_128_ecb();
        break;
    case 24:
        aes_cipher = EVP_aes_192_ecb();
        break;
    case 32:
        aes_cipher = EVP_aes_256_ecb();
        break;
    default:
        return 0;
    }

    c = malloc(sizeof(*c));
    if (c == NULL)
        return 0;

    c->aes_ctx = EVP_CIPHER_CTX_new();
    if (c->aes_ctx == NULL) {
        free(c);
        return 0;
    }

    if (EVP_EncryptInit(c->aes_ctx, aes_cipher, key, NULL) != 1) {
        free(c->aes_ctx);
        free(c);
        return 0;
    }

    EVP_CIPHER_CTX_set_padding(c->aes_ctx, 0);

    memcpy(c->ctr, iv, AES_BLOCK_SIZE);

    EVP_CIPHER_CTX_set_app_data(ctx, c);

    return 1;
}

static int
aes_ctr_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                  const unsigned char *in,
                  size_t inl) /* encrypt/decrypt data */
{
    aes_ctr_ctx *c = EVP_CIPHER_CTX_get_app_data(ctx);
    unsigned char b1[AES_BLOCK_SIZE];
    size_t i = 0;
    int outlen = 0;

    if (inl != 16) /* libssh2 only ever encrypt one block */
        return 0;

    if (c == NULL) {
        return 0;
    }

/*
  To encrypt a packet P=P1||P2||...||Pn (where P1, P2, ..., Pn are each
  blocks of length L), the encryptor first encrypts <X> with <cipher>
  to obtain a block B1.  The block B1 is then XORed with P1 to generate
  the ciphertext block C1.  The counter X is then incremented
*/

    if (EVP_EncryptUpdate(c->aes_ctx, b1, &outlen, c->ctr, AES_BLOCK_SIZE) != 1) {
        return 0;
    }

    for (i = 0; i < 16; i++)
        *out++ = *in++ ^ b1[i];

    i = 15;
    while (c->ctr[i]++ == 0xFF) {
        if (i == 0)
            break;
        i--;
    }

    return 1;
}

static int
aes_ctr_cleanup(EVP_CIPHER_CTX *ctx) /* cleanup ctx */
{
    aes_ctr_ctx *c = EVP_CIPHER_CTX_get_app_data(ctx);

    if (c == NULL) {
        return 1;
    }

    if (c->aes_ctx != NULL) {
        _libssh2_cipher_dtor(&(c->aes_ctx));
        free(c->aes_ctx);
    }

    free(c);

    return 1;
}

static const EVP_CIPHER *
make_ctr_evp (size_t keylen, EVP_CIPHER **aes_ctr_cipher)
{
    if (*aes_ctr_cipher == NULL) {
        *aes_ctr_cipher = EVP_CIPHER_meth_new(0, 16, keylen);
        if (*aes_ctr_cipher != NULL) {
            EVP_CIPHER_meth_set_iv_length(*aes_ctr_cipher, 16);
            EVP_CIPHER_meth_set_init(*aes_ctr_cipher, aes_ctr_init);
            EVP_CIPHER_meth_set_do_cipher(*aes_ctr_cipher, aes_ctr_do_cipher);
            EVP_CIPHER_meth_set_cleanup(*aes_ctr_cipher, aes_ctr_cleanup);
        }
    }

    return *aes_ctr_cipher;
}

const EVP_CIPHER *
_libssh2_EVP_aes_128_ctr(void)
{
    static EVP_CIPHER *aes_ctr_cipher;
    return make_ctr_evp(16, &aes_ctr_cipher);
}

const EVP_CIPHER *
_libssh2_EVP_aes_192_ctr(void)
{
    static EVP_CIPHER *aes_ctr_cipher;
    return make_ctr_evp(24, &aes_ctr_cipher);
}

const EVP_CIPHER *
_libssh2_EVP_aes_256_ctr(void)
{
    static EVP_CIPHER *aes_ctr_cipher;
    return make_ctr_evp(32, &aes_ctr_cipher);
}

void _libssh2_init_aes_ctr(void)
{
    _libssh2_EVP_aes_128_ctr();
    _libssh2_EVP_aes_192_ctr();
    _libssh2_EVP_aes_256_ctr();
}

#else
void _libssh2_init_aes_ctr(void) {}
#endif /* LIBSSH2_AES_CTR */

/* TODO: Optionally call a passphrase callback specified by the
 * calling program
 */
static int
passphrase_cb(char *buf, int size, int rwflag, char *passphrase)
{
    int passphrase_len = strlen(passphrase);
    (void) rwflag;

    if (passphrase_len > (size - 1)) {
        passphrase_len = size - 1;
    }
    memcpy(buf, passphrase, passphrase_len);
    buf[passphrase_len] = '\0';

    return passphrase_len;
}

typedef void * (*pem_read_bio_func)(BIO *, void **, pem_password_cb *,
                                    void * u);

static int
read_private_key_from_memory(void ** key_ctx,
                             pem_read_bio_func read_private_key,
                             const char * filedata,
                             size_t filedata_len,
                             unsigned const char *passphrase)
{
    BIO * bp;

    *key_ctx = NULL;

    bp = BIO_new_mem_buf((char *)filedata, filedata_len);
    if (!bp) {
        return -1;
    }
    *key_ctx = read_private_key(bp, NULL, (pem_password_cb *) passphrase_cb,
                                (void *) passphrase);

    BIO_free(bp);
    return (*key_ctx) ? 0 : -1;
}

static int
read_private_key_from_file(void ** key_ctx,
                           pem_read_bio_func read_private_key,
                           const char * filename,
                           unsigned const char *passphrase)
{
    BIO * bp;

    *key_ctx = NULL;

    bp = BIO_new_file(filename, "r");
    if (!bp) {
        return -1;
    }

    *key_ctx = read_private_key(bp, NULL, (pem_password_cb *) passphrase_cb,
                                (void *) passphrase);

    BIO_free(bp);
    return (*key_ctx) ? 0 : -1;
}

int
_libssh2_rsa_new_private_frommemory(libssh2_rsa_ctx ** rsa,
                                    LIBSSH2_SESSION * session,
                                    const char *filedata, size_t filedata_len,
                                    unsigned const char *passphrase)
{
    pem_read_bio_func read_rsa =
        (pem_read_bio_func) &PEM_read_bio_RSAPrivateKey;
    (void) session;

    _libssh2_init_if_needed();

    return read_private_key_from_memory((void **) rsa, read_rsa,
                                        filedata, filedata_len, passphrase);
}

int
_libssh2_rsa_new_private(libssh2_rsa_ctx ** rsa,
                         LIBSSH2_SESSION * session,
                         const char *filename, unsigned const char *passphrase)
{
    pem_read_bio_func read_rsa =
        (pem_read_bio_func) &PEM_read_bio_RSAPrivateKey;
    (void) session;

    _libssh2_init_if_needed ();

    return read_private_key_from_file((void **) rsa, read_rsa,
                                      filename, passphrase);
}

#if LIBSSH2_DSA
int
_libssh2_dsa_new_private_frommemory(libssh2_dsa_ctx ** dsa,
                                    LIBSSH2_SESSION * session,
                                    const char *filedata, size_t filedata_len,
                                    unsigned const char *passphrase)
{
    pem_read_bio_func read_dsa =
        (pem_read_bio_func) &PEM_read_bio_DSAPrivateKey;
    (void) session;

    _libssh2_init_if_needed();

    return read_private_key_from_memory((void **) dsa, read_dsa,
                                        filedata, filedata_len, passphrase);
}

int
_libssh2_dsa_new_private(libssh2_dsa_ctx ** dsa,
                         LIBSSH2_SESSION * session,
                         const char *filename, unsigned const char *passphrase)
{
    pem_read_bio_func read_dsa =
        (pem_read_bio_func) &PEM_read_bio_DSAPrivateKey;
    (void) session;

    _libssh2_init_if_needed ();

    return read_private_key_from_file((void **) dsa, read_dsa,
                                      filename, passphrase);
}
#endif /* LIBSSH_DSA */

int
_libssh2_rsa_sha1_sign(LIBSSH2_SESSION * session,
                       libssh2_rsa_ctx * rsactx,
                       const unsigned char *hash,
                       size_t hash_len,
                       unsigned char **signature, size_t *signature_len)
{
    int ret;
    unsigned char *sig;
    unsigned int sig_len;

    sig_len = RSA_size(rsactx);
    sig = LIBSSH2_ALLOC(session, sig_len);

    if (!sig) {
        return -1;
    }

    ret = RSA_sign(NID_sha1, hash, hash_len, sig, &sig_len, rsactx);

    if (!ret) {
        LIBSSH2_FREE(session, sig);
        return -1;
    }

    *signature = sig;
    *signature_len = sig_len;

    return 0;
}

#if LIBSSH2_DSA
int
_libssh2_dsa_sha1_sign(libssh2_dsa_ctx * dsactx,
                       const unsigned char *hash,
                       unsigned long hash_len, unsigned char *signature)
{
    DSA_SIG *sig;
    const BIGNUM *r, *s;
    int r_len, s_len;
    (void) hash_len;

    sig = DSA_do_sign(hash, SHA_DIGEST_LENGTH, dsactx);
    if (!sig) {
        return -1;
    }

    DSA_SIG_get0(sig, &r, &s);
    r_len = BN_num_bytes(r);
    if (r_len < 1 || r_len > 20) {
        DSA_SIG_free(sig);
        return -1;
    }
    s_len = BN_num_bytes(s);
    if (s_len < 1 || s_len > 20) {
        DSA_SIG_free(sig);
        return -1;
    }

    memset(signature, 0, 40);

    BN_bn2bin(r, signature + (20 - r_len));
    BN_bn2bin(s, signature + 20 + (20 - s_len));

    DSA_SIG_free(sig);

    return 0;
}
#endif /* LIBSSH_DSA */

void
_libssh2_digest_final(libssh2_md5_ctx ctx, unsigned char *out)
{
    EVP_DigestFinal(ctx, out, NULL);
    EVP_MD_CTX_free(ctx);
}

int
_libssh2_sha1_init(libssh2_sha1_ctx *ctx)
{
    EVP_MD_CTX_init(*ctx);
    return EVP_DigestInit(*ctx, EVP_get_digestbyname("sha1"));
}

int
_libssh2_sha1(const unsigned char *message, unsigned long len,
              unsigned char *out)
{
    EVP_MD_CTX *ctx;

    ctx = EVP_MD_CTX_new();
    if (EVP_DigestInit(ctx, EVP_get_digestbyname("sha1"))) {
        EVP_DigestUpdate(ctx, message, len);
        EVP_DigestFinal(ctx, out, NULL);
        EVP_MD_CTX_free(ctx);
        return 0; /* success */
    }
    EVP_MD_CTX_free(ctx);
    return 1; /* error */
}

int
_libssh2_sha256_init(libssh2_sha256_ctx *ctx)
{
    EVP_MD_CTX_init(*ctx);
    return EVP_DigestInit(*ctx, EVP_get_digestbyname("sha256"));
}

int
_libssh2_sha256(const unsigned char *message, unsigned long len,
                unsigned char *out)
{
    EVP_MD_CTX *ctx;

    ctx = EVP_MD_CTX_new();
    if(EVP_DigestInit(ctx, EVP_get_digestbyname("sha256"))) {
        EVP_DigestUpdate(ctx, message, len);
        EVP_DigestFinal(ctx, out, NULL);
        EVP_MD_CTX_free(ctx);
        return 0; /* success */
    }
    EVP_MD_CTX_free(ctx);
    return 1; /* error */
}

int
_libssh2_md5_init(libssh2_md5_ctx *ctx)
{
    EVP_MD_CTX_init(*ctx);
    return EVP_DigestInit(*ctx, EVP_get_digestbyname("md5"));
}

static unsigned char *
write_bn(unsigned char *buf, const BIGNUM *bn, int bn_bytes)
{
    unsigned char *p = buf;

    /* Left space for bn size which will be written below. */
    p += 4;

    *p = 0;
    BN_bn2bin(bn, p + 1);
    if (!(*(p + 1) & 0x80)) {
        memmove(p, p + 1, --bn_bytes);
    }
    _libssh2_htonu32(p - 4, bn_bytes);  /* Post write bn size. */

    return p + bn_bytes;
}

static unsigned char *
gen_publickey_from_rsa(LIBSSH2_SESSION *session, RSA *rsa,
                       size_t *key_len)
{
    const BIGNUM *e, *n;
    int            e_bytes, n_bytes;
    unsigned long  len;
    unsigned char* key;
    unsigned char* p;

    RSA_get0_key(rsa, &n, &e, NULL);
    e_bytes = BN_num_bytes(e) + 1;
    n_bytes = BN_num_bytes(n) + 1;

    /* Key form is "ssh-rsa" + e + n. */
    len = 4 + 7 + 4 + e_bytes + 4 + n_bytes;

    key = LIBSSH2_ALLOC(session, len);
    if (key == NULL) {
        return NULL;
    }

    /* Process key encoding. */
    p = key;

    _libssh2_htonu32(p, 7);  /* Key type. */
    p += 4;
    memcpy(p, "ssh-rsa", 7);
    p += 7;

    p = write_bn(p, e, e_bytes);
    p = write_bn(p, n, n_bytes);

    *key_len = (size_t)(p - key);
    return key;
}

#if LIBSSH2_DSA
static unsigned char *
gen_publickey_from_dsa(LIBSSH2_SESSION* session, DSA *dsa,
                       size_t *key_len)
{
    const BIGNUM *pn, *qn, *gn, *pub_key;
    int            p_bytes, q_bytes, g_bytes, k_bytes;
    unsigned long  len;
    unsigned char* key;
    unsigned char* p;

    DSA_get0_pqg(dsa, &pn, &qn, &gn);
    p_bytes = BN_num_bytes(pn) + 1;
    q_bytes = BN_num_bytes(qn) + 1;
    g_bytes = BN_num_bytes(gn) + 1;
    DSA_get0_key(dsa, &pub_key, NULL);
    k_bytes = BN_num_bytes(pub_key) + 1;

    /* Key form is "ssh-dss" + p + q + g + pub_key. */
    len = 4 + 7 + 4 + p_bytes + 4 + q_bytes + 4 + g_bytes + 4 + k_bytes;

    key = LIBSSH2_ALLOC(session, len);
    if (key == NULL) {
        return NULL;
    }

    /* Process key encoding. */
    p = key;

    _libssh2_htonu32(p, 7);  /* Key type. */
    p += 4;
    memcpy(p, "ssh-dss", 7);
    p += 7;

    p = write_bn(p, pn, p_bytes);
    p = write_bn(p, qn, q_bytes);
    p = write_bn(p, gn, g_bytes);
    p = write_bn(p, pub_key, k_bytes);

    *key_len = (size_t)(p - key);
    return key;
}
#endif /* LIBSSH_DSA */

static int
gen_publickey_from_rsa_evp(LIBSSH2_SESSION *session,
                           unsigned char **method,
                           size_t *method_len,
                           unsigned char **pubkeydata,
                           size_t *pubkeydata_len,
                           EVP_PKEY *pk)
{
    RSA*           rsa = NULL;
    unsigned char* key;
    unsigned char* method_buf = NULL;
    size_t  key_len;

    _libssh2_debug(session,
                   LIBSSH2_TRACE_AUTH,
                   "Computing public key from RSA private key envelop");

    rsa = EVP_PKEY_get1_RSA(pk);
    if (rsa == NULL) {
        /* Assume memory allocation error... what else could it be ? */
        goto __alloc_error;
    }

    method_buf = LIBSSH2_ALLOC(session, 7);  /* ssh-rsa. */
    if (method_buf == NULL) {
        goto __alloc_error;
    }

    key = gen_publickey_from_rsa(session, rsa, &key_len);
    if (key == NULL) {
        goto __alloc_error;
    }
    RSA_free(rsa);

    memcpy(method_buf, "ssh-rsa", 7);
    *method         = method_buf;
    *method_len     = 7;
    *pubkeydata     = key;
    *pubkeydata_len = key_len;
    return 0;

  __alloc_error:
    if (rsa != NULL) {
        RSA_free(rsa);
    }
    if (method_buf != NULL) {
        LIBSSH2_FREE(session, method_buf);
    }

    return _libssh2_error(session,
                          LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for private key data");
}

#if LIBSSH2_DSA
static int
gen_publickey_from_dsa_evp(LIBSSH2_SESSION *session,
                           unsigned char **method,
                           size_t *method_len,
                           unsigned char **pubkeydata,
                           size_t *pubkeydata_len,
                           EVP_PKEY *pk)
{
    DSA*           dsa = NULL;
    unsigned char* key;
    unsigned char* method_buf = NULL;
    size_t  key_len;

    _libssh2_debug(session,
                   LIBSSH2_TRACE_AUTH,
                   "Computing public key from DSA private key envelop");

    dsa = EVP_PKEY_get1_DSA(pk);
    if (dsa == NULL) {
        /* Assume memory allocation error... what else could it be ? */
        goto __alloc_error;
    }

    method_buf = LIBSSH2_ALLOC(session, 7);  /* ssh-dss. */
    if (method_buf == NULL) {
        goto __alloc_error;
    }

    key = gen_publickey_from_dsa(session, dsa, &key_len);
    if (key == NULL) {
        goto __alloc_error;
    }
    DSA_free(dsa);

    memcpy(method_buf, "ssh-dss", 7);
    *method         = method_buf;
    *method_len     = 7;
    *pubkeydata     = key;
    *pubkeydata_len = key_len;
    return 0;

  __alloc_error:
    if (dsa != NULL) {
        DSA_free(dsa);
    }
    if (method_buf != NULL) {
        LIBSSH2_FREE(session, method_buf);
    }

    return _libssh2_error(session,
                          LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for private key data");
}
#endif /* LIBSSH_DSA */

int
_libssh2_pub_priv_keyfile(LIBSSH2_SESSION *session,
                          unsigned char **method,
                          size_t *method_len,
                          unsigned char **pubkeydata,
                          size_t *pubkeydata_len,
                          const char *privatekey,
                          const char *passphrase)
{
    int       st;
    BIO*      bp;
    EVP_PKEY* pk;

    _libssh2_debug(session,
                   LIBSSH2_TRACE_AUTH,
                   "Computing public key from private key file: %s",
                   privatekey);

    bp = BIO_new_file(privatekey, "r");
    if (bp == NULL) {
        return _libssh2_error(session,
                              LIBSSH2_ERROR_FILE,
                              "Unable to extract public key from private key "
                              "file: Unable to open private key file");
    }
    if (!EVP_get_cipherbyname("des")) {
        /* If this cipher isn't loaded it's a pretty good indication that none
         * are.  I have *NO DOUBT* that there's a better way to deal with this
         * ($#&%#$(%$#( Someone buy me an OpenSSL manual and I'll read up on
         * it.
         */
        OpenSSL_add_all_ciphers();
    }
    BIO_reset(bp);
    pk = PEM_read_bio_PrivateKey(bp, NULL, NULL, (void*)passphrase);
    BIO_free(bp);

    if (pk == NULL) {
        return _libssh2_error(session,
                              LIBSSH2_ERROR_FILE,
                              "Unable to extract public key "
                              "from private key file: "
                              "Wrong passphrase or invalid/unrecognized "
                              "private key file format");
    }

    switch (EVP_PKEY_base_id(pk)) {
    case EVP_PKEY_RSA :
        st = gen_publickey_from_rsa_evp(
            session, method, method_len, pubkeydata, pubkeydata_len, pk);
        break;

#if LIBSSH2_DSA
    case EVP_PKEY_DSA :
        st = gen_publickey_from_dsa_evp(
            session, method, method_len, pubkeydata, pubkeydata_len, pk);
        break;
#endif /* LIBSSH_DSA */

    default :
        st = _libssh2_error(session,
                            LIBSSH2_ERROR_FILE,
                            "Unable to extract public key "
                            "from private key file: "
                            "Unsupported private key file format");
        break;
    }

    EVP_PKEY_free(pk);
    return st;
}

int
_libssh2_pub_priv_keyfilememory(LIBSSH2_SESSION *session,
                                unsigned char **method,
                                size_t *method_len,
                                unsigned char **pubkeydata,
                                size_t *pubkeydata_len,
                                const char *privatekeydata,
                                size_t privatekeydata_len,
                                const char *passphrase)
{
    int       st;
    BIO*      bp;
    EVP_PKEY* pk;

    _libssh2_debug(session,
                   LIBSSH2_TRACE_AUTH,
                   "Computing public key from private key.");

    bp = BIO_new_mem_buf((char *)privatekeydata, privatekeydata_len);
    if (!bp) {
        return -1;
    }
    if (!EVP_get_cipherbyname("des")) {
        /* If this cipher isn't loaded it's a pretty good indication that none
         * are.  I have *NO DOUBT* that there's a better way to deal with this
         * ($#&%#$(%$#( Someone buy me an OpenSSL manual and I'll read up on
         * it.
         */
        OpenSSL_add_all_ciphers();
    }
    BIO_reset(bp);
    pk = PEM_read_bio_PrivateKey(bp, NULL, NULL, (void*)passphrase);
    BIO_free(bp);

    if (pk == NULL) {
        return _libssh2_error(session,
                              LIBSSH2_ERROR_FILE,
                              "Unable to extract public key "
                              "from private key file: "
                              "Wrong passphrase or invalid/unrecognized "
                              "private key file format");
    }

    switch (EVP_PKEY_base_id(pk)) {
    case EVP_PKEY_RSA :
        st = gen_publickey_from_rsa_evp(session, method, method_len,
                                        pubkeydata, pubkeydata_len, pk);
        break;
#if LIBSSH2_DSA
    case EVP_PKEY_DSA :
        st = gen_publickey_from_dsa_evp(session, method, method_len,
                                        pubkeydata, pubkeydata_len, pk);
        break;
#endif /* LIBSSH_DSA */
    default :
        st = _libssh2_error(session,
                            LIBSSH2_ERROR_FILE,
                            "Unable to extract public key "
                            "from private key file: "
                            "Unsupported private key file format");
        break;
    }

    EVP_PKEY_free(pk);
    return st;
}

#endif /* LIBSSH2_OPENSSL */
