# attestation — TPM を使ったアテステーションの流れを一通り確かめる

`attest_flow` は、TPM を使ったリモートアテステーションの流れを、1本のプログラムで一通り試すものです。
次の2つを組み合わせています。

- riv_attester_test の I 群で行っている credential activation
- このリポジトリの `Quote/` / `checkquote/` で行っている Quote の作成と検証

| 役割 | ファイル | 中身 |
|---|---|---|
| Attester | `attester.c` | ESAPI で TPM を直接操作する。EK・AK の生成、ActivateCredential、PCR16 への測定値の記録、Quote、PCR_Read |
| Verifier | `verifier.c`、`makecred.c` | TPM を使わず OpenSSL で独立に計算する。公開鍵の検査、MakeCredential、Quote の検証 |
| 流れと結果の表示 | `attest_flow.c` | 上の2つを交互に呼び、項目ごとに `[PASS]` / `[FAIL]` / `[SKIP]` を出す |

`makecred.[ch]` は riv_attester_test の `ubuntu/makecred.[ch]` から写したものです。

## 鍵

| 鍵 | 階層 | 種類 |
|---|---|---|
| EK | endorsement | TCG EK Credential Profile のテンプレート L-2(ECC P-256、restricted decrypt、AES-128-CFB、PolicySecret(endorsement)) |
| AK | owner | ECC P-256 / ECDSA-SHA256 の restricted 署名鍵 |

- どちらも primary key として作るので、同じ TPM では毎回同じ鍵になります。
- 終了時に捨てるので、TPM には何も残りません。
- 既存の `Quote/` は RSA の AK を使っていますが、ここでは MakeCredential の実装に合わせて ECC にしています。

## 流れとテスト項目

```
Verifier(OpenSSL)                     Attester(TPM)
                                       K: EK・AK を作る
K: 公開鍵を検査、AK の Name を計算 ←── 公開鍵
C: MakeCredential(EK, AK の Name) ──→  ActivateCredential(AK, EK)
   復元値が自分の乱数と一致するか ←──   復元値
Q: nonce ─────────────────────────→  PCR16 に測定値を記録、Quote、PCR_Read
   署名・nonce・pcrDigest・PCR16 ←──   Quote、署名、PCR 値
N: 再送・改ざん・別の鍵・測定値の変化を見破れるか
```

| ID | 内容 |
|---|---|
| K1、K2 | EK・AK を作れる |
| K3 | EK 公開鍵が MakeCredential の前提(ECC P-256、SHA-256、AES-128-CFB、restricted decrypt)を満たす |
| K4 | AK 公開鍵が Quote 用の鍵の属性(restricted 署名、fixedTPM、fixedParent、sensitiveDataOrigin、ECDSA-SHA256)を持つ |
| K5 | Verifier が計算した AK の Name が、TPM の Name と一致する |
| C1、C2 | ActivateCredential が成功し、復元された値が Verifier の乱数と一致する(AK と EK が同じ TPM にある) |
| C3〜C5 | 違う Name に束縛、HMAC の改ざん、別の EK 宛ての credential を TPM が拒否する |
| Q1 | PCR16 をリセットして測定値を1回 extend し、PCR0〜7・16 を Quote できる |
| Q2〜Q5 | magic、type、extraData = nonce、PCR 選択 |
| Q6 | 署名を、activation 済みの AK の公開鍵で検証できる |
| Q7 | PCR_Read の値から再計算した pcrDigest が一致する |
| Q8 | PCR16 が期待値(Reference Value)= SHA-256(0³² ∥ 測定値) と一致する |
| N1 | 古い Quote を新しい nonce で検証すると不合格(再送の検知) |
| N2 | Quote を1bit改ざんすると署名検証が不合格 |
| N3 | activation していない別の鍵では署名検証が不合格 |
| N4 | 測定値が変わると、署名と pcrDigest は合格のまま、Reference Value の照合だけが不合格 |

SKIP になる場合があります。
- C2 が不合格なら、C3〜C5 を SKIP にします。正しい credential が通らないと、拒否された理由を区別できないためです。
- activation が不合格なら、Q 群を SKIP にします。TPM にあると確かめていない AK の Quote は信用する根拠が無いためです。
- 正しい Quote が合格しなければ、N 群を SKIP にします。

## ビルドと実行

```sh
sudo apt-get install -y libtss2-dev libssl-dev swtpm
make
make run                       # 使い捨ての swtpm で実行(./run-swtpm.sh)
./attest_flow --tcti device:/dev/tpmrm0   # 実 TPM(通常は sudo か tss グループ)
```

- 終了コードは、全項目合格なら 0、不合格があれば 1、引数の誤りや TPM に接続できない場合は 2 です。
- C3〜C5 では TPM がわざと拒否するので、ESYS のエラーログは既定で止めています。見たいときは `TSS2_LOG=esys+warning ./attest_flow ...` のように指定します。

## 注意

- **PCR16 をリセットします。** PCR16 はデバッグ用の PCR です。実 TPM で動かすと、ほかのツールが PCR16 に記録していた値は消えます。
- **PCR0〜7 は照合しません。** Quote と pcrDigest の整合は確かめますが、起動時の測定値の期待値を持っていないためです。
- **このプログラムが保証しないことがあります。**
  - EK 証明書を検証していないので、「本物の TPM である」ことまでは確かめていません。
  - Attester と Verifier が同じプロセスにあるので、鍵の受け渡しは信頼できる経路を前提にしています。

  ここで確かめているのは、TPM と ESAPI を使った手順と、Verifier の検証ロジックが正しく動くことです。

## 動作確認

swtpm 0.7.3(`make run`)で PASS 22 / FAIL 0 / SKIP 0(2026-10-20)。
