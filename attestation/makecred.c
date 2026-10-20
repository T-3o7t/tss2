/*
 * makecred.c — TPM2_MakeCredential のソフトウェア実装。makecred.h を参照。
 * riv_attester_test の ubuntu/makecred.c から写したもの(ファイル読み込みの
 * tpm_load_public は不要なので外した)。
 *
 *   Z           = ECDH(一時鍵, EK) の x 座標
 *   seed        = KDFe(SHA-256, Z, "IDENTITY", 一時鍵.x, EK.x, 256)
 *   symKey      = KDFa(SHA-256, seed, "STORAGE", name, -, 128)
 *   encIdentity = AES-128-CFB(symKey, IV=0, TPM2B_DIGEST(credential))
 *   hmacKey     = KDFa(SHA-256, seed, "INTEGRITY", -, -, 256)
 *   outerHMAC   = HMAC-SHA256(hmacKey, encIdentity ∥ name)
 *   blob        = TPM2B_ID_OBJECT(TPM2B_DIGEST(outerHMAC) ∥ encIdentity)
 *   secret      = TPM2B_ENCRYPTED_SECRET(TPMS_ECC_POINT(一時鍵の公開点))
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/param_build.h>

#include <tss2/tss2_mu.h>

#include "makecred.h"

#define SEED_LEN 32   /* EK の nameAlg(SHA-256)のダイジェスト長 */
#define SYM_LEN  16   /* EK の symmetric(AES-128) */
#define COORD    32   /* P-256 の座標長 */

EVP_PKEY *tpm_ecc_to_evp(const TPM2B_PUBLIC *pub)
{
    const TPM2B_ECC_PARAMETER *x, *y;
    uint8_t point[1 + 2 * COORD];
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    if (pub->publicArea.type != TPM2_ALG_ECC ||
        pub->publicArea.parameters.eccDetail.curveID != TPM2_ECC_NIST_P256) {
        fprintf(stderr, "ECC P-256のみ対応 (type=0x%x)\n",
                pub->publicArea.type);
        return NULL;
    }
    x = &pub->publicArea.unique.ecc.x;
    y = &pub->publicArea.unique.ecc.y;
    if (x->size > COORD || y->size > COORD)
        return NULL;
    memset(point, 0, sizeof(point));
    point[0] = 0x04;
    memcpy(point + 1 + (COORD - x->size), x->buffer, x->size);
    memcpy(point + 1 + COORD + (COORD - y->size), y->buffer, y->size);

    bld = OSSL_PARAM_BLD_new();
    if (bld &&
        OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                        "prime256v1", 0) &&
        OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, point,
                                         sizeof(point)))
        params = OSSL_PARAM_BLD_to_param(bld);
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!params || !ctx || EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
        pkey = NULL;
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return pkey;
}

int tpm_name_of(const TPM2B_PUBLIC *pub, uint8_t name[TPM_NAME_LEN])
{
    uint8_t buf[sizeof(TPMT_PUBLIC)];
    size_t off = 0;
    unsigned int dlen = 0;

    if (pub->publicArea.nameAlg != TPM2_ALG_SHA256 ||
        Tss2_MU_TPMT_PUBLIC_Marshal(&pub->publicArea, buf, sizeof(buf),
                                    &off) != TSS2_RC_SUCCESS)
        return -1;
    name[0] = (uint8_t)(TPM2_ALG_SHA256 >> 8);
    name[1] = (uint8_t)TPM2_ALG_SHA256;
    if (!EVP_Digest(buf, off, name + 2, &dlen, EVP_sha256(), NULL) ||
        dlen != 32)
        return -1;
    return 0;
}

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* KDFa(SHA-256): HMAC(key, i ∥ label\0 ∥ ctxU ∥ ctxV ∥ bits) を連結 */
static int kdfa(const uint8_t *key, size_t key_len, const char *label,
                const uint8_t *ctx_u, size_t u_len, const uint8_t *ctx_v,
                size_t v_len, uint8_t *out, size_t out_len)
{
    uint32_t i;
    size_t done = 0;

    uint8_t msg[4 + 32 + 2 * 64 + 4];
    size_t llen = strlen(label) + 1, mlen;

    if (llen > 32 || u_len > 64 || v_len > 64)
        return -1;
    for (i = 1; done < out_len; i++) {
        uint8_t md[32];
        unsigned int mdlen = 0;

        put_u32(msg, i);
        mlen = 4;
        memcpy(msg + mlen, label, llen);
        mlen += llen;
        if (u_len)
            memcpy(msg + mlen, ctx_u, u_len);
        mlen += u_len;
        if (v_len)
            memcpy(msg + mlen, ctx_v, v_len);
        mlen += v_len;
        put_u32(msg + mlen, (uint32_t)(out_len * 8));
        mlen += 4;
        if (!HMAC(EVP_sha256(), key, (int)key_len, msg, mlen, md, &mdlen))
            return -1;
        memcpy(out + done, md,
               out_len - done < mdlen ? out_len - done : mdlen);
        done += mdlen;
    }
    return 0;
}

/* KDFe(SHA-256): H(i ∥ Z ∥ label\0 ∥ partyU ∥ partyV) を連結 */
static int kdfe(const uint8_t *z, size_t z_len, const char *label,
                const uint8_t *party_u, size_t u_len,
                const uint8_t *party_v, size_t v_len,
                uint8_t *out, size_t out_len)
{
    uint32_t i;
    size_t done = 0;

    for (i = 1; done < out_len; i++) {
        uint8_t ctr[4], md[32];
        unsigned int mdlen = 0;
        EVP_MD_CTX *c = EVP_MD_CTX_new();
        int ok;

        put_u32(ctr, i);
        ok = c && EVP_DigestInit_ex(c, EVP_sha256(), NULL) &&
             EVP_DigestUpdate(c, ctr, 4) && EVP_DigestUpdate(c, z, z_len) &&
             EVP_DigestUpdate(c, label, strlen(label) + 1) &&
             EVP_DigestUpdate(c, party_u, u_len) &&
             EVP_DigestUpdate(c, party_v, v_len) &&
             EVP_DigestFinal_ex(c, md, &mdlen);
        EVP_MD_CTX_free(c);
        if (!ok)
            return -1;
        memcpy(out + done, md,
               out_len - done < mdlen ? out_len - done : mdlen);
        done += mdlen;
    }
    return 0;
}

/* EC 公開鍵の (x, y) を取り出す(非圧縮形式) */
static int ec_point_xy(EVP_PKEY *k, uint8_t x[COORD], uint8_t y[COORD])
{
    uint8_t pt[1 + 2 * COORD];
    size_t len = 0;

    if (!EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                         pt, sizeof(pt), &len) ||
        len != sizeof(pt) || pt[0] != 0x04)
        return -1;
    memcpy(x, pt + 1, COORD);
    memcpy(y, pt + 1 + COORD, COORD);
    return 0;
}

int make_credential(EVP_PKEY *ek, const uint8_t *name, size_t name_len,
                    const uint8_t *cred, size_t cred_len,
                    uint8_t *blob, size_t blob_cap, size_t *blob_len,
                    uint8_t *secret, size_t secret_cap, size_t *secret_len)
{
    EVP_PKEY *eph = NULL;
    EVP_PKEY_CTX *dctx = NULL;
    EVP_CIPHER_CTX *cctx = NULL;
    uint8_t ek_x[COORD], ek_y[COORD], eph_x[COORD], eph_y[COORD];
    uint8_t z[COORD], seed[SEED_LEN], sym[SYM_LEN], hkey[32];
    uint8_t iv[16] = {0}, plain[2 + 64], enc[2 + 64 + 64], hmac[32];
    unsigned int hlen = 0;
    size_t zlen = sizeof(z), plen, off;
    int outl = 0, fin = 0, rc = -1;
    TPMS_ECC_POINT pt;
    TPM2B_ENCRYPTED_SECRET es;
    TPM2B_ID_OBJECT id;
    TPM2B_DIGEST d;

    if (!cred_len || cred_len > 64)
        return -1;
    if (ec_point_xy(ek, ek_x, ek_y) < 0)
        return -1;

    /* 一時鍵と ECDH */
    eph = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    if (!eph || ec_point_xy(eph, eph_x, eph_y) < 0)
        goto out;
    dctx = EVP_PKEY_CTX_new(eph, NULL);
    if (!dctx || EVP_PKEY_derive_init(dctx) <= 0 ||
        EVP_PKEY_derive_set_peer(dctx, ek) <= 0 ||
        EVP_PKEY_derive(dctx, z, &zlen) <= 0 || zlen != COORD)
        goto out;

    if (kdfe(z, zlen, "IDENTITY", eph_x, COORD, ek_x, COORD, seed,
             sizeof(seed)) < 0 ||
        kdfa(seed, sizeof(seed), "STORAGE", name, name_len, NULL, 0, sym,
             sizeof(sym)) < 0 ||
        kdfa(seed, sizeof(seed), "INTEGRITY", NULL, 0, NULL, 0, hkey,
             sizeof(hkey)) < 0)
        goto out;

    /* encIdentity = AES-128-CFB(TPM2B_DIGEST(credential)) */
    memset(&d, 0, sizeof(d));
    d.size = (UINT16)cred_len;
    memcpy(d.buffer, cred, cred_len);
    plen = 0;
    if (Tss2_MU_TPM2B_DIGEST_Marshal(&d, plain, sizeof(plain), &plen) !=
        TSS2_RC_SUCCESS)
        goto out;
    cctx = EVP_CIPHER_CTX_new();
    if (!cctx ||
        !EVP_EncryptInit_ex(cctx, EVP_aes_128_cfb128(), NULL, sym, iv) ||
        !EVP_EncryptUpdate(cctx, enc, &outl, plain, (int)plen) ||
        !EVP_EncryptFinal_ex(cctx, enc + outl, &fin) ||
        (size_t)(outl + fin) != plen)
        goto out;

    /* outerHMAC = HMAC(hmacKey, encIdentity ∥ name) */
    if (name_len > 64)
        goto out;
    memcpy(enc + plen, name, name_len); /* encの後ろを作業域に使う */
    if (!HMAC(EVP_sha256(), hkey, sizeof(hkey), enc, plen + name_len, hmac,
              &hlen) ||
        hlen != sizeof(hmac))
        goto out;

    /* blob = TPM2B_ID_OBJECT(TPM2B_DIGEST(outerHMAC) ∥ encIdentity) */
    memset(&id, 0, sizeof(id));
    id.credential[0] = 0;
    id.credential[1] = (uint8_t)hlen;
    memcpy(id.credential + 2, hmac, hlen);
    memcpy(id.credential + 2 + hlen, enc, plen);
    id.size = (UINT16)(2 + hlen + plen);
    off = 0;
    if (Tss2_MU_TPM2B_ID_OBJECT_Marshal(&id, blob, blob_cap, &off) !=
        TSS2_RC_SUCCESS)
        goto out;
    *blob_len = off;

    /* secret = TPM2B_ENCRYPTED_SECRET(TPMS_ECC_POINT(一時鍵)) */
    memset(&pt, 0, sizeof(pt));
    pt.x.size = COORD;
    memcpy(pt.x.buffer, eph_x, COORD);
    pt.y.size = COORD;
    memcpy(pt.y.buffer, eph_y, COORD);
    memset(&es, 0, sizeof(es));
    off = 0;
    if (Tss2_MU_TPMS_ECC_POINT_Marshal(&pt, es.secret,
                                       sizeof(es.secret), &off) !=
        TSS2_RC_SUCCESS)
        goto out;
    es.size = (UINT16)off;
    off = 0;
    if (Tss2_MU_TPM2B_ENCRYPTED_SECRET_Marshal(&es, secret, secret_cap,
                                               &off) != TSS2_RC_SUCCESS)
        goto out;
    *secret_len = off;
    rc = 0;
out:
    EVP_CIPHER_CTX_free(cctx);
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(eph);
    OPENSSL_cleanse(seed, sizeof(seed));
    OPENSSL_cleanse(sym, sizeof(sym));
    OPENSSL_cleanse(hkey, sizeof(hkey));
    return rc;
}
