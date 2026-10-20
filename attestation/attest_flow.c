/*
 * attest_flow.c — TPM を使ったリモートアテステーションの流れを一通り確かめる。
 *
 * 1本のプログラムの中で、Attester 側(attester.c、ESAPI で TPM を操作)と
 * Verifier 側(verifier.c、OpenSSL で独立に計算)を交互に動かす。
 *
 *   K 鍵の準備             EK・AK を作り、Verifier が公開鍵を検査する
 *   C credential activation  AK が EK と同じ TPM にあることを確かめる
 *   Q Quote                nonce と PCR(0〜7、16)を AK で署名させて検証する
 *   N 攻撃・誤りの検知     再送、改ざん、別の鍵、測定値の変化を見破れるか
 *
 * PCR16 はリセットしてから既知の測定値を1回 extend する。Verifier はその
 * 期待値を計算できるので、Reference Value との照合(Q8)ができる。
 * PCR0〜7 は起動時の測定値で、期待値が無いため照合はしない。
 *
 * 使い方: attest_flow [--tcti STR]
 *   STR の例: swtpm:host=127.0.0.1,port=2321 / device:/dev/tpmrm0
 *   省略時は tctildr の既定(環境変数 TPM2TOOLS_TCTI など)
 * 終了コード: 0=全項目合格、1=不合格あり、2=引数の誤り・準備の失敗
 *
 * C3〜C5 では TPM がわざと拒否するので、ESYS のエラーログは既定で止めて
 * いる。見たいときは TSS2_LOG=esys+warning などを指定して実行する。
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <tss2/tss2_rc.h>

#include "attester.h"
#include "makecred.h"
#include "verifier.h"

#define NONCE_LEN 32
#define CRED_LEN  32

/* ---- 結果の表示 ---- */

static int n_pass, n_fail, n_skip;

static void group(const char *title)
{
    printf("\n== %s ==\n", title);
}

static int check(const char *id, const char *name, int cond,
                 const char *fmt, ...)
{
    if (cond) {
        printf("[PASS] %-3s %s\n", id, name);
        n_pass++;
    } else {
        va_list ap;

        printf("[FAIL] %-3s %s: ", id, name);
        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);
        printf("\n");
        n_fail++;
    }
    return cond;
}

static void skip(const char *id, const char *name, const char *why)
{
    printf("[SKIP] %-3s %s: %s\n", id, name, why);
    n_skip++;
}

static void info_hex(const char *label, const uint8_t *p, size_t n)
{
    size_t i;

    printf("       %s", label);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static void info(const char *fmt, ...)
{
    va_list ap;

    printf("       ");
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}

static const char *rc_str(TSS2_RC rc)
{
    return rc == TSS2_RC_SUCCESS ? "成功" : Tss2_RC_Decode(rc);
}

/* ---- 準備 ---- */

/* sha256 バンクの PCR0〜7 と PCR16 */
static void make_selection(TPML_PCR_SELECTION *sel)
{
    memset(sel, 0, sizeof(*sel));
    sel->count = 1;
    sel->pcrSelections[0].hash = TPM2_ALG_SHA256;
    sel->pcrSelections[0].sizeofSelect = 3;
    sel->pcrSelections[0].pcrSelect[0] = 0xFF; /* PCR0〜7 */
    sel->pcrSelections[0].pcrSelect[2] = 0x01; /* PCR16 */
}

/* 測定値の代わり: ラベル文字列の SHA-256 */
static void measurement_of(const char *label, uint8_t out[32])
{
    unsigned int len = 0;

    EVP_Digest(label, strlen(label), out, &len, EVP_sha256(), NULL);
}

/* 1回分の Quote(PCR16 の測定 → Quote → PCR_Read) */
typedef struct {
    uint8_t nonce[NONCE_LEN];
    TPM2B_ATTEST quote;
    TPMT_SIGNATURE sig;
    pcr_values pcrs;
} evidence;

static TSS2_RC collect(attester *a, const TPML_PCR_SELECTION *sel,
                       const uint8_t measurement[32], evidence *ev)
{
    TSS2_RC rc;

    memset(ev, 0, sizeof(*ev));
    if (RAND_bytes(ev->nonce, NONCE_LEN) != 1)
        return TSS2_ESYS_RC_GENERAL_FAILURE;
    rc = att_measure(a, measurement);
    if (rc == TSS2_RC_SUCCESS)
        rc = att_quote(a, ev->nonce, NONCE_LEN, sel, &ev->quote, &ev->sig);
    if (rc == TSS2_RC_SUCCESS)
        rc = att_pcr_read(a, sel, &ev->pcrs);
    return rc;
}

static void usage(void)
{
    fprintf(stderr, "usage: attest_flow [--tcti STR]\n");
}

int main(int argc, char **argv)
{
    const char *tcti = NULL;
    attester a;
    TPM2B_PUBLIC ek_pub, ak_pub;
    TPM2B_NAME tpm_name;
    EVP_PKEY *ek = NULL, *ak = NULL, *other = NULL;
    uint8_t name[TPM_NAME_LEN], bad_name[TPM_NAME_LEN];
    uint8_t cred[CRED_LEN], m_good[32], m_bad[32], ref16[32];
    TPM2B_ID_OBJECT blob;
    TPM2B_ENCRYPTED_SECRET secret;
    TPM2B_DIGEST got;
    TPML_PCR_SELECTION sel;
    evidence ev, ev2;
    quote_result qr;
    char why[160];
    TSS2_RC rc;
    int i, keys_ok, activated = 0;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--tcti") && i + 1 < argc) {
            tcti = argv[++i];
        } else {
            usage();
            return 2;
        }
    }

    setenv("TSS2_LOG", "esys+none", 0); /* 指定があればそちらを優先 */
    rc = att_init(&a, tcti);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "TPM に接続できない: %s\n", rc_str(rc));
        att_fini(&a);
        return 2;
    }
    make_selection(&sel);
    measurement_of("attest_flow: expected measurement", m_good);
    measurement_of("attest_flow: tampered measurement", m_bad);
    vf_pcr16_expected(m_good, ref16);

    /* ===== K: 鍵の準備 ===== */
    group("K 鍵の準備(Attester が作り、Verifier が公開鍵を検査する)");
    rc = att_create_ek(&a, &ek_pub);
    check("K1", "EK を作れる(endorsement 階層、L-2 テンプレート)",
          rc == TSS2_RC_SUCCESS, "%s", rc_str(rc));
    if (rc != TSS2_RC_SUCCESS)
        goto done;
    rc = att_create_ak(&a, &ak_pub);
    check("K2", "AK を作れる(owner 階層、ECC P-256 の restricted 署名鍵)",
          rc == TSS2_RC_SUCCESS, "%s", rc_str(rc));
    if (rc != TSS2_RC_SUCCESS)
        goto done;

    why[0] = 0;
    keys_ok = check("K3", "EK 公開鍵が MakeCredential の前提を満たす",
                    vf_check_ek(&ek_pub, why, sizeof(why)) == 0, "%s", why);
    why[0] = 0;
    keys_ok &= check("K4", "AK 公開鍵が Quote 用の鍵の属性を持つ",
                     vf_check_ak(&ak_pub, why, sizeof(why)) == 0, "%s", why);
    ek = tpm_ecc_to_evp(&ek_pub);
    ak = tpm_ecc_to_evp(&ak_pub);
    keys_ok &= ek && ak;
    rc = att_ak_name(&a, &tpm_name);
    keys_ok &= check("K5", "Verifier が計算した AK の Name が TPM の Name と一致",
                     rc == TSS2_RC_SUCCESS && tpm_name_of(&ak_pub, name) == 0 &&
                         tpm_name.size == TPM_NAME_LEN &&
                         memcmp(tpm_name.name, name, TPM_NAME_LEN) == 0,
                     "%s", rc == TSS2_RC_SUCCESS ? "Name が違う" : rc_str(rc));
    if (!keys_ok) {
        printf("       鍵の検査に通らないため、以降は実行しない\n");
        goto done;
    }
    info_hex("AK の Name: ", name, TPM_NAME_LEN);

    /* ===== C: credential activation ===== */
    group("C credential activation(AK が EK と同じ TPM にあるか)");
    RAND_bytes(cred, CRED_LEN);
    if (vf_make_credential(ek, name, TPM_NAME_LEN, cred, CRED_LEN, &blob,
                           &secret) < 0) {
        check("C1", "MakeCredential(Verifier)", 0, "credential を作れない");
        goto done;
    }
    rc = att_activate(&a, &blob, &secret, &got);
    check("C1", "ActivateCredential が成功する", rc == TSS2_RC_SUCCESS, "%s",
          rc_str(rc));
    activated = check("C2", "復元された値が Verifier の乱数と一致する",
                      rc == TSS2_RC_SUCCESS && got.size == CRED_LEN &&
                          memcmp(got.buffer, cred, CRED_LEN) == 0,
                      "%s", rc == TSS2_RC_SUCCESS ? "値が違う" : "C1 が不合格");

    /* C3〜C5 は「正しい credential なら通る」ことが前提。C2 が通らないと、
     * 拒否の理由が束縛先・HMAC・宛先の違いなのか区別できない */
    if (!activated) {
        skip("C3-5", "Name・HMAC・EK の違いによる拒否", "C2 が不合格");
    } else {
        memcpy(bad_name, name, TPM_NAME_LEN);
        bad_name[TPM_NAME_LEN - 1] ^= 0x01;
        RAND_bytes(cred, CRED_LEN);
        vf_make_credential(ek, bad_name, TPM_NAME_LEN, cred, CRED_LEN, &blob,
                           &secret);
        rc = att_activate(&a, &blob, &secret, &got);
        check("C3", "AK と違う Name に束縛した credential を TPM が拒否する",
              rc != TSS2_RC_SUCCESS, "復元できてしまった");
        if (rc != TSS2_RC_SUCCESS)
            info("TPM の応答: %s", rc_str(rc));

        vf_make_credential(ek, name, TPM_NAME_LEN, cred, CRED_LEN, &blob,
                           &secret);
        blob.credential[2] ^= 0x01; /* TPM2B_DIGEST(outerHMAC) の先頭 */
        rc = att_activate(&a, &blob, &secret, &got);
        check("C4", "HMAC を1bit変えた credential を TPM が拒否する",
              rc != TSS2_RC_SUCCESS, "復元できてしまった");
        if (rc != TSS2_RC_SUCCESS)
            info("TPM の応答: %s", rc_str(rc));

        other = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
        if (other && vf_make_credential(other, name, TPM_NAME_LEN, cred,
                                        CRED_LEN, &blob, &secret) == 0) {
            rc = att_activate(&a, &blob, &secret, &got);
            check("C5", "別の EK 宛てに作った credential を TPM が拒否する",
                  rc != TSS2_RC_SUCCESS, "復元できてしまった");
            if (rc != TSS2_RC_SUCCESS)
                info("TPM の応答: %s", rc_str(rc));
        } else {
            check("C5", "別の EK 宛てに作った credential を TPM が拒否する", 0,
                  "比較用の鍵を作れない");
        }
    }

    /* ===== Q: Quote ===== */
    group("Q Quote(nonce と PCR0〜7・16 を AK で署名させて検証する)");
    if (!activated) {
        /* 同居を確かめていない AK の Quote は信用する根拠が無い */
        skip("Q1-8", "Quote の検証", "AK の credential activation が不合格");
        goto negative;
    }
    rc = collect(&a, &sel, m_good, &ev);
    check("Q1", "PCR16 に測定値を記録して Quote できる", rc == TSS2_RC_SUCCESS,
          "%s", rc_str(rc));
    if (rc != TSS2_RC_SUCCESS)
        goto done;
    vf_verify_quote(&ev.quote, &ev.sig, ak, ev.nonce, NONCE_LEN, &sel,
                    &ev.pcrs, ref16, &qr);
    check("Q2", "TPMS_ATTEST の magic が TPM_GENERATED_VALUE",
          qr.parsed && qr.magic, "%s", qr.why);
    check("Q3", "TPMS_ATTEST の type が ATTEST_QUOTE", qr.type, "%s", qr.why);
    check("Q4", "extraData が Verifier の nonce と一致", qr.nonce, "%s", qr.why);
    check("Q5", "quote 内の PCR 選択が要求どおり", qr.selection, "%s", qr.why);
    check("Q6", "署名を activation 済みの AK で検証できる", qr.signature, "%s",
          qr.why);
    check("Q7", "PCR 値から再計算した pcrDigest が一致", qr.digest, "%s",
          qr.why);
    check("Q8", "PCR16 が期待値(Reference Value)と一致", qr.reference, "%s",
          qr.why);
    info_hex("PCR16: ", ev.pcrs.value[16], 32);

negative:
    /* ===== N: 攻撃・誤りの検知 ===== */
    group("N 攻撃・誤りの検知(Verifier が見破れるか)");
    if (!activated || !vf_quote_ok(&qr, 1)) {
        skip("N1-4", "攻撃・誤りの検知", "正しい Quote が合格していない");
        goto done;
    }
    {
        uint8_t fresh[NONCE_LEN];

        RAND_bytes(fresh, NONCE_LEN);
        vf_verify_quote(&ev.quote, &ev.sig, ak, fresh, NONCE_LEN, &sel,
                        &ev.pcrs, ref16, &qr);
        check("N1", "古い Quote を新しい nonce で検証すると不合格(再送の検知)",
              !qr.nonce && !vf_quote_ok(&qr, 1), "合格してしまった");
    }
    {
        TPM2B_ATTEST t = ev.quote;

        t.attestationData[t.size - 1] ^= 0x01; /* pcrDigest の末尾 */
        vf_verify_quote(&t, &ev.sig, ak, ev.nonce, NONCE_LEN, &sel, &ev.pcrs,
                        ref16, &qr);
        check("N2", "Quote を1bit改ざんすると署名検証が不合格",
              !qr.signature, "合格してしまった");
    }
    {
        EVP_PKEY *fake = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");

        vf_verify_quote(&ev.quote, &ev.sig, fake, ev.nonce, NONCE_LEN, &sel,
                        &ev.pcrs, ref16, &qr);
        check("N3", "activation していない別の鍵では署名検証が不合格",
              fake && !qr.signature, "合格してしまった");
        EVP_PKEY_free(fake);
    }
    rc = collect(&a, &sel, m_bad, &ev2);
    if (rc != TSS2_RC_SUCCESS) {
        check("N4", "測定値が変わると Reference Value の照合が不合格", 0,
              "Quote できない: %s", rc_str(rc));
    } else {
        vf_verify_quote(&ev2.quote, &ev2.sig, ak, ev2.nonce, NONCE_LEN, &sel,
                        &ev2.pcrs, ref16, &qr);
        /* 署名と pcrDigest は正しい(TPM は正直に報告している)が、
         * 測定値が期待と違うことを Reference Value で見つける */
        check("N4", "測定値が変わると Reference Value の照合だけが不合格",
              qr.signature && qr.digest && !qr.reference,
              "signature=%d digest=%d reference=%d", qr.signature, qr.digest,
              qr.reference);
    }

done:
    EVP_PKEY_free(ek);
    EVP_PKEY_free(ak);
    EVP_PKEY_free(other);
    att_fini(&a);
    printf("\n結果: PASS %d / FAIL %d / SKIP %d\n", n_pass, n_fail, n_skip);
    if (n_fail == 0 && n_pass == 0)
        return 2;
    return n_fail ? 1 : 0;
}
