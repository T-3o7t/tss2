/*
 * attester.h — Attester 側: ESAPI で TPM を直接操作する。
 *
 * EK はTCG EK Credential Profile のテンプレート L-2(ECC P-256)で endorsement
 * 階層に、AK は ECC P-256 / ECDSA-SHA256 の restricted 署名鍵として owner
 * 階層に、どちらも primary key として作る(seed から決まるので同じ TPM では
 * 毎回同じ鍵になる)。
 */
#ifndef ATTESTER_H
#define ATTESTER_H

#include <stdint.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

/* Quote の対象にする PCR の上限(sha256 バンクの PCR0〜23) */
#define ATT_MAX_PCR 24

typedef struct {
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *ectx;
    ESYS_TR ek;
    ESYS_TR ak;
} attester;

/* sha256 バンクの PCR 値。have[i] が立っている番号だけ value[i] が有効 */
typedef struct {
    uint8_t have[ATT_MAX_PCR];
    uint8_t value[ATT_MAX_PCR][32];
} pcr_values;

/* tcti_str が NULL なら tctildr の既定(環境変数 TPM2TOOLS_TCTI など) */
TSS2_RC att_init(attester *a, const char *tcti_str);
void att_fini(attester *a);

TSS2_RC att_create_ek(attester *a, TPM2B_PUBLIC *out);
TSS2_RC att_create_ak(attester *a, TPM2B_PUBLIC *out);
/* TPM が保持している AK の Name */
TSS2_RC att_ak_name(attester *a, TPM2B_NAME *out);

/* AK(activateHandle)と EK(keyHandle)で credential を復元する */
TSS2_RC att_activate(attester *a, const TPM2B_ID_OBJECT *blob,
                     const TPM2B_ENCRYPTED_SECRET *secret,
                     TPM2B_DIGEST *out);

/* PCR16 をリセットして measurement(32B)を1回 extend する */
TSS2_RC att_measure(attester *a, const uint8_t measurement[32]);

TSS2_RC att_quote(attester *a, const uint8_t *nonce, size_t nonce_len,
                  const TPML_PCR_SELECTION *sel, TPM2B_ATTEST *quote,
                  TPMT_SIGNATURE *sig);
TSS2_RC att_pcr_read(attester *a, const TPML_PCR_SELECTION *sel,
                     pcr_values *out);

#endif
