#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_rc.h>

#define CHECK_RC(rc, msg)                                              \
    do {                                                               \
        if ((rc) != TSS2_RC_SUCCESS) {                                 \
            fprintf(stderr, "%s failed: 0x%x\n", (msg), (rc));         \
            goto cleanup;                                              \
        }                                                              \
    } while (0)

static int read_binary_file(const char *path, unsigned char **buf, size_t *len)
{
    FILE *fp = fopen(path, "rb");
    long sz;

    if (!fp) return -1;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return -1; }
    sz = ftell(fp);
    if (sz < 0) { fclose(fp); return -1; }
    rewind(fp);

    *buf = malloc((size_t)sz);
    if (!*buf) { fclose(fp); return -1; }

    if (fread(*buf, 1, (size_t)sz, fp) != (size_t)sz) {
        fclose(fp);
        free(*buf);
        *buf = NULL;
        return -1;
    }

    fclose(fp);
    *len = (size_t)sz;
    return 0;
}

int main(int argc, char *argv[]){

    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    ESYS_CONTEXT *ctx = NULL;

    unsigned char *data_buf = NULL;
    size_t data_len = 0;

    unsigned char *sig_buf = NULL;
    size_t sig_len = 0;

    TPM2B_DIGEST digest = {0};
    TPMT_SIGNATURE signature = {0};
    TPMT_TK_VERIFIED *validation = NULL;

    ESYS_TR keyHandle = ESYS_TR_NONE;

    TPM2_HANDLE persistentHandle = 0x81010001;

    if (read_binary_file(argv[1], &data_buf, &data_len) != 0) {
        fprintf(stderr, "failed to read data.bin\n");
        return 1;
    }

    if (read_binary_file("sig.bin", &sig_buf, &sig_len) != 0) {
        fprintf(stderr, "failed to read sig.bin\n");
        free(data_buf);
        return 1;
    }

    if (data_len > 0) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(data_buf, data_len, hash);

        digest.size = SHA256_DIGEST_LENGTH;
        memcpy(digest.buffer, hash, SHA256_DIGEST_LENGTH);
    } else {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((const unsigned char *)"", 0, hash);

        digest.size = SHA256_DIGEST_LENGTH;
        memcpy(digest.buffer, hash, SHA256_DIGEST_LENGTH);
    }

    signature.sigAlg = TPM2_ALG_RSASSA;
    signature.signature.rsassa.hash = TPM2_ALG_SHA256;

    if (sig_len > sizeof(signature.signature.rsassa.sig.buffer)) {
        fprintf(stderr, "signature too large\n");
        free(data_buf);
        free(sig_buf);
        return 1;
    }

    signature.signature.rsassa.sig.size = (UINT16)sig_len;
    memcpy(signature.signature.rsassa.sig.buffer, sig_buf, sig_len);

    rc = Tss2_TctiLdr_Initialize(NULL, &tcti);
    CHECK_RC(rc, "Tss2_TctiLdr_Initialize");

    rc = Esys_Initialize(&ctx, tcti, NULL);
    CHECK_RC(rc, "Esys_Initialize");

    rc = Esys_TR_FromTPMPublic(
        ctx,
        persistentHandle,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        &keyHandle
    );
    CHECK_RC(rc, "Esys_TR_FromTPMPublic");

    rc = Esys_VerifySignature(
        ctx,
        keyHandle,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        &digest,
        &signature,
        &validation
    );
    CHECK_RC(rc, "Esys_VerifySignature");

    printf("Verified OK\n");

cleanup:
    if (validation) {
        Esys_Free(validation);
    }
    if (keyHandle != ESYS_TR_NONE) {
        Esys_TR_Close(ctx, &keyHandle);
    }
    if (ctx) {
        Esys_Finalize(&ctx);
    }
    if (tcti) {
        Tss2_TctiLdr_Finalize(&tcti);
    }
    free(data_buf);
    free(sig_buf);

    return (rc == TSS2_RC_SUCCESS) ? 0 : 1;
}
