/*
 * makecred.h — TPM2_MakeCredential のソフトウェア実装(ECC P-256 の EK 用)。
 * riv_attester_test の ubuntu/makecred.h から写したもの。
 *
 * Verifier 側で TPM を使わずに credential を作るためのもの。
 * TPM 2.0 Part 1「Credential Protection」(24章)と
 * Part 1 附属書 C(ECC の Secret Sharing、KDFe)に従う。
 * EK のテンプレートは TCG EK Credential Profile の L-2
 * (ECC P-256、nameAlg=SHA-256、AES-128-CFB)を前提とする。
 */
#ifndef RIV_MAKECRED_H
#define RIV_MAKECRED_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <tss2/tss2_tpm2_types.h>

#define TPM_NAME_LEN 34 /* nameAlg(2) ∥ SHA-256(32) */

/* ECC P-256 の TPM2B_PUBLIC を EVP_PKEY(公開鍵)へ。失敗時 NULL */
EVP_PKEY *tpm_ecc_to_evp(const TPM2B_PUBLIC *pub);

/* オブジェクトの Name = nameAlg ∥ SHA-256(TPMT_PUBLIC)。0=成功 */
int tpm_name_of(const TPM2B_PUBLIC *pub, uint8_t name[TPM_NAME_LEN]);

/*
 * ek 宛てに、name のオブジェクトに束縛した credential を作る。
 * blob   ← TPM2B_ID_OBJECT のマーシャル形式(CRED_BLOB の value)
 * secret ← TPM2B_ENCRYPTED_SECRET のマーシャル形式(CRED_SECRET の value)
 * 0=成功、-1=失敗
 */
int make_credential(EVP_PKEY *ek, const uint8_t *name, size_t name_len,
                    const uint8_t *cred, size_t cred_len,
                    uint8_t *blob, size_t blob_cap, size_t *blob_len,
                    uint8_t *secret, size_t secret_cap, size_t *secret_len);

#endif
