/*
 * attester.c — Attester 側: ESAPI で TPM を直接操作する。attester.h を参照。
 */
#include <stdio.h>
#include <string.h>

#include "attester.h"

/* PolicySecret(TPM_RH_ENDORSEMENT) のポリシーダイジェスト
 * (TCG EK Credential Profile、テンプレート L-2 の authPolicy) */
static const uint8_t ek_policy[32] = {
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8,
    0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
    0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64,
    0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa
};

TSS2_RC att_init(attester *a, const char *tcti_str)
{
    TSS2_RC rc;

    memset(a, 0, sizeof(*a));
    a->ek = ESYS_TR_NONE;
    a->ak = ESYS_TR_NONE;
    rc = Tss2_TctiLdr_Initialize(tcti_str, &a->tcti);
    if (rc != TSS2_RC_SUCCESS)
        return rc;
    return Esys_Initialize(&a->ectx, a->tcti, NULL);
}

void att_fini(attester *a)
{
    /* リソースマネージャの無い TPM(swtpm 直結など)では、捨てないと
     * プロセス終了後も transient 枠に残る */
    if (a->ectx) {
        if (a->ak != ESYS_TR_NONE)
            Esys_FlushContext(a->ectx, a->ak);
        if (a->ek != ESYS_TR_NONE)
            Esys_FlushContext(a->ectx, a->ek);
        Esys_Finalize(&a->ectx);
    }
    if (a->tcti)
        Tss2_TctiLdr_Finalize(&a->tcti);
}

static TSS2_RC create_primary(attester *a, ESYS_TR hierarchy,
                              const TPM2B_PUBLIC *tmpl, ESYS_TR *handle,
                              TPM2B_PUBLIC *out)
{
    TPM2B_SENSITIVE_CREATE in_sensitive = {0};
    TPM2B_DATA outside_info = {0};
    TPML_PCR_SELECTION creation_pcr = {0};
    TPM2B_PUBLIC *pub = NULL;
    TSS2_RC rc;

    rc = Esys_CreatePrimary(a->ectx, hierarchy,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            &in_sensitive, tmpl, &outside_info, &creation_pcr,
                            handle, &pub, NULL, NULL, NULL);
    if (rc == TSS2_RC_SUCCESS) {
        *out = *pub;
        Esys_Free(pub);
    }
    return rc;
}

/* EK: TCG EK Credential Profile テンプレート L-2
 * (ECC P-256、restricted decrypt、AES-128-CFB、PolicySecret(endorsement)) */
TSS2_RC att_create_ek(attester *a, TPM2B_PUBLIC *out)
{
    TPM2B_PUBLIC t = {0};
    TPMS_ECC_PARMS *ecc = &t.publicArea.parameters.eccDetail;

    t.publicArea.type = TPM2_ALG_ECC;
    t.publicArea.nameAlg = TPM2_ALG_SHA256;
    t.publicArea.objectAttributes =
        TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
        TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_ADMINWITHPOLICY |
        TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT;
    t.publicArea.authPolicy.size = sizeof(ek_policy);
    memcpy(t.publicArea.authPolicy.buffer, ek_policy, sizeof(ek_policy));
    ecc->symmetric.algorithm = TPM2_ALG_AES;
    ecc->symmetric.keyBits.aes = 128;
    ecc->symmetric.mode.aes = TPM2_ALG_CFB;
    ecc->scheme.scheme = TPM2_ALG_NULL;
    ecc->curveID = TPM2_ECC_NIST_P256;
    ecc->kdf.scheme = TPM2_ALG_NULL;
    t.publicArea.unique.ecc.x.size = 32;
    t.publicArea.unique.ecc.y.size = 32;
    return create_primary(a, ESYS_TR_RH_ENDORSEMENT, &t, &a->ek, out);
}

/* AK: ECC P-256 / ECDSA-SHA256 の restricted 署名鍵 */
TSS2_RC att_create_ak(attester *a, TPM2B_PUBLIC *out)
{
    TPM2B_PUBLIC t = {0};
    TPMS_ECC_PARMS *ecc = &t.publicArea.parameters.eccDetail;

    t.publicArea.type = TPM2_ALG_ECC;
    t.publicArea.nameAlg = TPM2_ALG_SHA256;
    t.publicArea.objectAttributes =
        TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
        TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH |
        TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_SIGN_ENCRYPT;
    ecc->symmetric.algorithm = TPM2_ALG_NULL;
    ecc->scheme.scheme = TPM2_ALG_ECDSA;
    ecc->scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
    ecc->curveID = TPM2_ECC_NIST_P256;
    ecc->kdf.scheme = TPM2_ALG_NULL;
    return create_primary(a, ESYS_TR_RH_OWNER, &t, &a->ak, out);
}

TSS2_RC att_ak_name(attester *a, TPM2B_NAME *out)
{
    TPM2B_NAME *name = NULL;
    TSS2_RC rc = Esys_TR_GetName(a->ectx, a->ak, &name);

    if (rc == TSS2_RC_SUCCESS) {
        *out = *name;
        Esys_Free(name);
    }
    return rc;
}

/* AK はパスワード認可、EK は PolicySecret(TPM_RH_ENDORSEMENT) の
 * ポリシーセッションで認可する */
TSS2_RC att_activate(attester *a, const TPM2B_ID_OBJECT *blob,
                     const TPM2B_ENCRYPTED_SECRET *secret,
                     TPM2B_DIGEST *out)
{
    TPMT_SYM_DEF sym = {.algorithm = TPM2_ALG_NULL};
    ESYS_TR session = ESYS_TR_NONE;
    TPM2B_DIGEST *cert_info = NULL;
    TSS2_RC rc;

    rc = Esys_StartAuthSession(a->ectx, ESYS_TR_NONE, ESYS_TR_NONE,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               NULL, TPM2_SE_POLICY, &sym, TPM2_ALG_SHA256,
                               &session);
    if (rc != TSS2_RC_SUCCESS)
        return rc;
    rc = Esys_PolicySecret(a->ectx, ESYS_TR_RH_ENDORSEMENT, session,
                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                           NULL, NULL, NULL, 0, NULL, NULL);
    if (rc == TSS2_RC_SUCCESS)
        rc = Esys_ActivateCredential(a->ectx, a->ak, a->ek,
                                     ESYS_TR_PASSWORD, session, ESYS_TR_NONE,
                                     blob, secret, &cert_info);
    /* ESYS のセッションは既定で continueSession が立っており、成否に
     * よらず残るので毎回捨てる */
    Esys_FlushContext(a->ectx, session);
    if (rc == TSS2_RC_SUCCESS) {
        *out = *cert_info;
        Esys_Free(cert_info);
    }
    return rc;
}

/* PCR16 はデバッグ用でリセットできる。リセット後の値は全ゼロなので、
 * Verifier は SHA-256(0^32 ∥ measurement) を期待値として再計算できる */
TSS2_RC att_measure(attester *a, const uint8_t measurement[32])
{
    TPML_DIGEST_VALUES v = {0};
    TSS2_RC rc;

    rc = Esys_PCR_Reset(a->ectx, ESYS_TR_PCR16,
                        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
    if (rc != TSS2_RC_SUCCESS)
        return rc;
    v.count = 1;
    v.digests[0].hashAlg = TPM2_ALG_SHA256;
    memcpy(v.digests[0].digest.sha256, measurement, 32);
    return Esys_PCR_Extend(a->ectx, ESYS_TR_PCR16,
                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &v);
}

TSS2_RC att_quote(attester *a, const uint8_t *nonce, size_t nonce_len,
                  const TPML_PCR_SELECTION *sel, TPM2B_ATTEST *quote,
                  TPMT_SIGNATURE *sig)
{
    TPM2B_DATA qual = {0};
    TPMT_SIG_SCHEME scheme = {.scheme = TPM2_ALG_NULL}; /* AK の既定の方式 */
    TPM2B_ATTEST *q = NULL;
    TPMT_SIGNATURE *s = NULL;
    TSS2_RC rc;

    if (nonce_len > sizeof(qual.buffer))
        return TSS2_ESYS_RC_BAD_VALUE;
    qual.size = (UINT16)nonce_len;
    memcpy(qual.buffer, nonce, nonce_len);
    rc = Esys_Quote(a->ectx, a->ak,
                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                    &qual, &scheme, sel, &q, &s);
    if (rc == TSS2_RC_SUCCESS) {
        *quote = *q;
        *sig = *s;
        Esys_Free(q);
        Esys_Free(s);
    }
    return rc;
}

/* PCR_Read は1回で返る数に上限があるため、返ってきた分を要求から
 * 落としながら繰り返す */
TSS2_RC att_pcr_read(attester *a, const TPML_PCR_SELECTION *sel,
                     pcr_values *out)
{
    TPML_PCR_SELECTION want = *sel;
    TSS2_RC rc;

    memset(out, 0, sizeof(*out));
    for (;;) {
        TPML_PCR_SELECTION *got = NULL;
        TPML_DIGEST *vals = NULL;
        UINT32 counter;
        uint32_t i, j, k = 0;
        int any = 0, progress = 0;

        for (i = 0; i < want.count; i++)
            for (j = 0; j < want.pcrSelections[i].sizeofSelect; j++)
                any |= want.pcrSelections[i].pcrSelect[j];
        if (!any)
            return TSS2_RC_SUCCESS;

        rc = Esys_PCR_Read(a->ectx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                           &want, &counter, &got, &vals);
        if (rc != TSS2_RC_SUCCESS)
            return rc;
        for (i = 0; i < got->count; i++) {
            const TPMS_PCR_SELECTION *s = &got->pcrSelections[i];

            for (j = 0; j < (uint32_t)s->sizeofSelect * 8; j++) {
                if (!(s->pcrSelect[j / 8] & (1u << (j % 8))))
                    continue;
                if (k >= vals->count)
                    break;
                if (s->hash == TPM2_ALG_SHA256 && j < ATT_MAX_PCR &&
                    vals->digests[k].size == 32) {
                    memcpy(out->value[j], vals->digests[k].buffer, 32);
                    out->have[j] = 1;
                }
                k++;
                progress = 1;
                for (uint32_t b = 0; b < want.count; b++)
                    if (want.pcrSelections[b].hash == s->hash)
                        want.pcrSelections[b].pcrSelect[j / 8] &=
                            (uint8_t)~(1u << (j % 8));
            }
        }
        Esys_Free(got);
        Esys_Free(vals);
        if (!progress)
            return TSS2_ESYS_RC_GENERAL_FAILURE;
    }
}
