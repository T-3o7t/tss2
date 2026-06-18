#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_esys.h>
static void save_rsassa_signature(const TPMT_SIGNATURE *sig, const char *path) {
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        perror("fopen");
        exit(1);
    }

    size_t written = fwrite(sig->signature.rsassa.sig.buffer,
                            1,
                            sig->signature.rsassa.sig.size,
                            fp);
    fclose(fp);

    if (written != sig->signature.rsassa.sig.size) {
        fprintf(stderr, "failed to write signature file\n");
        exit(1);
    }
}

static unsigned char *read_file(const char *path, size_t *out_size) {
    FILE *fp = fopen(path, "rb");
    unsigned char *buf;
    long sz;

    if (!fp) {
        perror("fopen");
        return NULL;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }

    sz = ftell(fp);
    if (sz < 0) {
        fclose(fp);
        return NULL;
    }

    rewind(fp);

    buf = malloc((size_t)sz);
    if (!buf) {
        fclose(fp);
        return NULL;
    }

    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf);
        fclose(fp);
        return NULL;
    }

    fclose(fp);
    *out_size = (size_t)sz;
    return buf;
}

int save_digest(const char *path, const TPM2B_DIGEST *digest)
{
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;

    size_t written = fwrite(digest->buffer, 1, digest->size, fp);
    fclose(fp);

    return (written == digest->size) ? 0 : -2;
}

int main(int argc,char *argv[])
{
    TSS2_RC r;
    ESYS_CONTEXT *ctx;

    // =========================
    // ESYS 初期化
    // =========================
    r = Esys_Initialize(
        &ctx,
        NULL,
        NULL
    );

    if (r != TSS2_RC_SUCCESS) {
        printf(
            "Esys_Initialize failed: 0x%x\n",
            r
        );
        return 1;
    }

    // =========================
    // persistent handle取得
    // =========================
    ESYS_TR keyHandle;

    r = Esys_TR_FromTPMPublic(
        ctx,
        0x81010001,   // persistent handle
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &keyHandle
    );
    //printf("TR_FromTPMPublic rc = 0x%x\n",r);

    if (r != TSS2_RC_SUCCESS) {

        printf(
            "Esys_TR_FromTPMPublic failed: 0x%x\n",
            r
        );

        Esys_Finalize(&ctx);

        return 1;
    }

    printf("Key handle loaded\n");

    // =========================
    // TPMでHash
    // =========================
    size_t data_size = 0;
    if(!argv[1]){
	    printf("Warning:required data file\n");
	    return 1;
    }

    const char *message = read_file(argv[1], &data_size);
        if (!message) {
            fprintf(stderr, "Failed to read data.txt\n");
            return 1;
    }

    TPM2B_MAX_BUFFER data = {
        .size = data_size
    };

    memcpy(
        data.buffer,
        message,
        data.size
    );

    TPM2B_DIGEST *digest = NULL;
    TPMT_TK_HASHCHECK *validation = NULL;

    r = Esys_Hash(
        ctx,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &data,
        TPM2_ALG_SHA256,
	ESYS_TR_RH_OWNER,
        &digest,
        &validation
    );

    if (r != TSS2_RC_SUCCESS) {

        printf(
            "Esys_Hash failed: 0x%x\n",
            r
        );

        Esys_TR_Close(ctx, &keyHandle);

        Esys_Finalize(&ctx);

        return 1;
    }

    printf(
        "Hash generated (%u bytes)\n",
        digest->size
    );
    
    save_digest("digest.bin", digest);
    printf("digest save to digest.bin\n");

    // =========================
    // RSA署名スキーム
    // =========================
    TPMT_SIG_SCHEME scheme = {
        .scheme = TPM2_ALG_RSASSA,
        .details = {
            .rsassa = {
                .hashAlg = TPM2_ALG_SHA256
            }
        }
    };

    TPMT_SIGNATURE *signature = NULL;
    TPM2B_AUTH emptyAuth = {
	    .size = 0
    };

    Esys_TR_SetAuth(
		    ctx,
		    keyHandle,
		    &emptyAuth
	 );

    // =========================
    // TPM署名
    // =========================
    r = Esys_Sign(
        ctx,
        keyHandle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        digest,
        &scheme,
        validation,
        &signature
    );

    if (r != TSS2_RC_SUCCESS) {

        printf(
            "Esys_Sign failed: 0x%x\n",
            r
        );

        Esys_Free(digest);

        Esys_Free(validation);

        Esys_TR_Close(ctx, &keyHandle);

        Esys_Finalize(&ctx);

        return 1;
    }

    // =========================
    // 署名表示
    // =========================
    printf(
        "Signature size: %u bytes\n",
        signature->signature.rsassa.sig.size
    );

    printf("Signature:\n");

    for (
        UINT16 i = 0;
        i < signature->signature.rsassa.sig.size;
        i++
    ) {
        printf(
            "%02X",
            signature->signature.rsassa.sig.buffer[i]
        );
    }

    printf("\n");
    if (signature->sigAlg == TPM2_ALG_RSASSA) {
        save_rsassa_signature(signature, "sig.bin");
        printf("signature saved to sig.bin\n");
    } else {
        fprintf(stderr, "unsupported signature algorithm: 0x%x\n", signature->sigAlg);
    }

    // =========================
    // cleanup
    // =========================
    Esys_Free(digest);

    Esys_Free(validation);

    Esys_Free(signature);

    Esys_TR_Close(
        ctx,
        &keyHandle
    );

    Esys_Finalize(&ctx);

    return 0;
}
