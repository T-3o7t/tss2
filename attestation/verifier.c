/*
 * verifier.c — Verifier 側: TPM を使わずに計算・検証する。verifier.h を参照。
 */
#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <tss2/tss2_mu.h>

#include "verifier.h"

#define WHY(...) snprintf(why, wcap, __VA_ARGS__)

int vf_check_ek(const TPM2B_PUBLIC *ek, char *why, size_t wcap)
{
    const TPMT_PUBLIC *p = &ek->publicArea;
    const TPMA_OBJECT need = TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT;

    if (p->type != TPM2_ALG_ECC ||
        p->parameters.eccDetail.curveID != TPM2_ECC_NIST_P256)
        return WHY("ECC P-256 でない"), -1;
    /* makecred.c は KDF のハッシュと暗号を決め打ちしている */
    if (p->nameAlg != TPM2_ALG_SHA256)
        return WHY("nameAlg が SHA-256 でない (0x%x)", p->nameAlg), -1;
    if (p->parameters.eccDetail.symmetric.algorithm != TPM2_ALG_AES ||
        p->parameters.eccDetail.symmetric.keyBits.aes != 128 ||
        p->parameters.eccDetail.symmetric.mode.aes != TPM2_ALG_CFB)
        return WHY("symmetric が AES-128-CFB でない"), -1;
    if ((p->objectAttributes & need) != need ||
        (p->objectAttributes & TPMA_OBJECT_SIGN_ENCRYPT))
        return WHY("restricted decrypt 鍵でない"), -1;
    return 0;
}

int vf_check_ak(const TPM2B_PUBLIC *ak, char *why, size_t wcap)
{
    const TPMT_PUBLIC *p = &ak->publicArea;
    const TPMA_OBJECT need =
        TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
        TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_RESTRICTED |
        TPMA_OBJECT_SIGN_ENCRYPT;

    if (p->type != TPM2_ALG_ECC ||
        p->parameters.eccDetail.curveID != TPM2_ECC_NIST_P256)
        return WHY("ECC P-256 でない"), -1;
    if (p->nameAlg != TPM2_ALG_SHA256)
        return WHY("nameAlg が SHA-256 でない"), -1;
    /* restricted でない署名鍵は、TPM 外で作ったデータにも署名できるので
     * Quote の根拠にならない。fixedTPM でなければ TPM の外に出せる */
    if ((p->objectAttributes & need) != need ||
        (p->objectAttributes & TPMA_OBJECT_DECRYPT))
        return WHY("restricted・fixedTPM・fixedParent・sensitiveDataOrigin の"
                   "署名鍵でない (attr=0x%x)", p->objectAttributes), -1;
    if (p->parameters.eccDetail.scheme.scheme != TPM2_ALG_ECDSA ||
        p->parameters.eccDetail.scheme.details.ecdsa.hashAlg !=
            TPM2_ALG_SHA256)
        return WHY("署名方式が ECDSA-SHA256 でない"), -1;
    return 0;
}

int vf_make_credential(EVP_PKEY *ek, const uint8_t *name, size_t name_len,
                       const uint8_t *cred, size_t cred_len,
                       TPM2B_ID_OBJECT *blob, TPM2B_ENCRYPTED_SECRET *secret)
{
    uint8_t b[sizeof(TPM2B_ID_OBJECT)], s[sizeof(TPM2B_ENCRYPTED_SECRET)];
    size_t blen = 0, slen = 0, off;

    if (make_credential(ek, name, name_len, cred, cred_len, b, sizeof(b),
                        &blen, s, sizeof(s), &slen) < 0)
        return -1;
    memset(blob, 0, sizeof(*blob));
    memset(secret, 0, sizeof(*secret));
    off = 0;
    if (Tss2_MU_TPM2B_ID_OBJECT_Unmarshal(b, blen, &off, blob) !=
        TSS2_RC_SUCCESS)
        return -1;
    off = 0;
    if (Tss2_MU_TPM2B_ENCRYPTED_SECRET_Unmarshal(s, slen, &off, secret) !=
        TSS2_RC_SUCCESS)
        return -1;
    return 0;
}

static int ecdsa_verify(EVP_PKEY *key, const TPMT_SIGNATURE *sig,
                        const uint8_t *msg, size_t len)
{
    ECDSA_SIG *es = ECDSA_SIG_new();
    BIGNUM *r, *s;
    uint8_t *der = NULL;
    int der_len, ok = 0;
    EVP_MD_CTX *md = NULL;

    if (!es || sig->sigAlg != TPM2_ALG_ECDSA ||
        sig->signature.ecdsa.hash != TPM2_ALG_SHA256) {
        ECDSA_SIG_free(es);
        return 0;
    }
    r = BN_bin2bn(sig->signature.ecdsa.signatureR.buffer,
                  sig->signature.ecdsa.signatureR.size, NULL);
    s = BN_bin2bn(sig->signature.ecdsa.signatureS.buffer,
                  sig->signature.ecdsa.signatureS.size, NULL);
    if (!r || !s || !ECDSA_SIG_set0(es, r, s)) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(es);
        return 0;
    }
    der_len = i2d_ECDSA_SIG(es, &der);
    md = EVP_MD_CTX_new();
    if (der_len > 0 && md &&
        EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, key) > 0)
        ok = EVP_DigestVerify(md, der, (size_t)der_len, msg, len) == 1;
    EVP_MD_CTX_free(md);
    OPENSSL_free(der);
    ECDSA_SIG_free(es);
    return ok;
}

static int same_selection(const TPML_PCR_SELECTION *a,
                          const TPML_PCR_SELECTION *b)
{
    uint32_t i, j;

    if (a->count != b->count)
        return 0;
    for (i = 0; i < a->count; i++) {
        const TPMS_PCR_SELECTION *x = &a->pcrSelections[i];
        const TPMS_PCR_SELECTION *y = &b->pcrSelections[i];
        uint8_t n = x->sizeofSelect > y->sizeofSelect ? x->sizeofSelect
                                                      : y->sizeofSelect;

        if (x->hash != y->hash)
            return 0;
        for (j = 0; j < n; j++) {
            uint8_t xv = j < x->sizeofSelect ? x->pcrSelect[j] : 0;
            uint8_t yv = j < y->sizeofSelect ? y->pcrSelect[j] : 0;

            if (xv != yv)
                return 0;
        }
    }
    return 1;
}

/* 選択の順(バンク順、番号の昇順)に PCR 値を連結した SHA-256 */
static int recompute_digest(const TPML_PCR_SELECTION *sel,
                            const pcr_values *pcrs, uint8_t out[32])
{
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    unsigned int len = 0;
    uint32_t i, j;
    int ok = md && EVP_DigestInit_ex(md, EVP_sha256(), NULL);

    for (i = 0; ok && i < sel->count; i++) {
        const TPMS_PCR_SELECTION *s = &sel->pcrSelections[i];

        if (s->hash != TPM2_ALG_SHA256) {
            ok = 0;
            break;
        }
        for (j = 0; ok && j < (uint32_t)s->sizeofSelect * 8; j++) {
            if (!(s->pcrSelect[j / 8] & (1u << (j % 8))))
                continue;
            if (j >= ATT_MAX_PCR || !pcrs->have[j]) {
                ok = 0;
                break;
            }
            ok = EVP_DigestUpdate(md, pcrs->value[j], 32);
        }
    }
    ok = ok && EVP_DigestFinal_ex(md, out, &len) && len == 32;
    EVP_MD_CTX_free(md);
    return ok;
}

void vf_pcr16_expected(const uint8_t measurement[32], uint8_t out[32])
{
    uint8_t buf[64] = {0};
    unsigned int len = 0;

    memcpy(buf + 32, measurement, 32);
    EVP_Digest(buf, sizeof(buf), out, &len, EVP_sha256(), NULL);
}

#define FAIL_WHY(...) \
    do { if (!r->why[0]) snprintf(r->why, sizeof(r->why), __VA_ARGS__); } \
    while (0)

void vf_verify_quote(const TPM2B_ATTEST *quote, const TPMT_SIGNATURE *sig,
                     EVP_PKEY *ak, const uint8_t *nonce, size_t nonce_len,
                     const TPML_PCR_SELECTION *sel, const pcr_values *pcrs,
                     const uint8_t *pcr16_ref, quote_result *r)
{
    TPMS_ATTEST att;
    size_t off = 0;
    uint8_t d[32];

    memset(r, 0, sizeof(*r));
    memset(&att, 0, sizeof(att));
    r->parsed = Tss2_MU_TPMS_ATTEST_Unmarshal(quote->attestationData,
                                              quote->size, &off, &att) ==
                    TSS2_RC_SUCCESS &&
                off == quote->size;
    if (!r->parsed) {
        FAIL_WHY("TPMS_ATTEST として解析できない");
        return;
    }
    r->magic = att.magic == TPM2_GENERATED_VALUE;
    if (!r->magic)
        FAIL_WHY("magic が TPM_GENERATED_VALUE でない (0x%08x)", att.magic);
    r->type = att.type == TPM2_ST_ATTEST_QUOTE;
    if (!r->type)
        FAIL_WHY("type が ATTEST_QUOTE でない (0x%04x)", att.type);
    r->nonce = att.extraData.size == nonce_len &&
               memcmp(att.extraData.buffer, nonce, nonce_len) == 0;
    if (!r->nonce)
        FAIL_WHY("extraData が送った nonce と一致しない");
    r->selection = same_selection(&att.attested.quote.pcrSelect, sel);
    if (!r->selection)
        FAIL_WHY("quote 内の PCR 選択が要求と違う");
    r->signature = ecdsa_verify(ak, sig, quote->attestationData, quote->size);
    if (!r->signature)
        FAIL_WHY("AK 公開鍵で署名を検証できない");
    r->digest = recompute_digest(sel, pcrs, d) &&
                att.attested.quote.pcrDigest.size == 32 &&
                memcmp(att.attested.quote.pcrDigest.buffer, d, 32) == 0;
    if (!r->digest)
        FAIL_WHY("PCR 値から再計算した pcrDigest が quote と一致しない");
    if (pcr16_ref) {
        r->reference = r->digest && pcrs->have[16] &&
                       memcmp(pcrs->value[16], pcr16_ref, 32) == 0;
        if (!r->reference)
            FAIL_WHY("PCR16 が期待値(Reference Value)と一致しない");
    }
}

int vf_quote_ok(const quote_result *r, int need_reference)
{
    return r->parsed && r->magic && r->type && r->nonce && r->selection &&
           r->signature && r->digest && (!need_reference || r->reference);
}
