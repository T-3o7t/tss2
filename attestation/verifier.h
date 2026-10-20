/*
 * verifier.h — Verifier 側: TPM を使わず OpenSSL と tss2-mu だけで計算する。
 *
 * Attester(TPM)と同じ実装を共有すると、両者に共通する解釈の誤りを
 * 見逃すため、MakeCredential も Quote の検証もソフトウェアで独立に行う。
 */
#ifndef VERIFIER_H
#define VERIFIER_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <tss2/tss2_tpm2_types.h>

#include "attester.h"
#include "makecred.h"

/* EK 公開鍵が MakeCredential の前提(ECC P-256、nameAlg=SHA-256、
 * AES-128-CFB、restricted decrypt)を満たすか。0=満たす(違えば why へ) */
int vf_check_ek(const TPM2B_PUBLIC *ek, char *why, size_t wcap);

/* AK 公開鍵が Quote 用の鍵の属性(restricted 署名、fixedTPM、fixedParent、
 * sensitiveDataOrigin、ECC P-256 / ECDSA-SHA256)を持つか。0=持つ */
int vf_check_ak(const TPM2B_PUBLIC *ak, char *why, size_t wcap);

/* ek 宛て・name 束縛の credential を作り、ESAPI に渡せる構造体で返す */
int vf_make_credential(EVP_PKEY *ek, const uint8_t *name, size_t name_len,
                       const uint8_t *cred, size_t cred_len,
                       TPM2B_ID_OBJECT *blob, TPM2B_ENCRYPTED_SECRET *secret);

/* Quote の検証結果。各項目 1=合格。why は最初の不合格の理由 */
typedef struct {
    int parsed;    /* TPMS_ATTEST として解析できる */
    int magic;     /* magic = TPM_GENERATED_VALUE */
    int type;      /* type = TPM_ST_ATTEST_QUOTE */
    int nonce;     /* extraData = 送った nonce */
    int selection; /* quote 内の PCR 選択 = 要求 */
    int signature; /* ECDSA 署名を AK 公開鍵で検証できる */
    int digest;    /* PCR 値から再計算した pcrDigest が一致 */
    int reference; /* PCR16 が期待値(Reference Value)と一致 */
    char why[160];
} quote_result;

/* quote と sig を検証する。pcr16_ref が NULL なら reference は判定しない */
void vf_verify_quote(const TPM2B_ATTEST *quote, const TPMT_SIGNATURE *sig,
                     EVP_PKEY *ak, const uint8_t *nonce, size_t nonce_len,
                     const TPML_PCR_SELECTION *sel, const pcr_values *pcrs,
                     const uint8_t *pcr16_ref, quote_result *r);

/* すべての項目が合格か */
int vf_quote_ok(const quote_result *r, int need_reference);

/* PCR16 の期待値: リセット後(全ゼロ)に measurement を1回 extend した値 */
void vf_pcr16_expected(const uint8_t measurement[32], uint8_t out[32]);

#endif
