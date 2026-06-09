#include <stdio.h>
#include <string.h>

#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_common.h>

static char *data_read(const char *path, size_t *out_size) {
    FILE *fp = fopen(path, "rb");
    char *buf;
    long sz;

    if(!fp){
        perror("fopen");
        exit(1);
    }

    if(fseek(fp, 0, SEEK_END) != 0){
        fclose(fp);
        exit(1);
    }

    sz = ftell(fp);
    if(sz < 0){
        fclose(fp);
        exit(1);
    }

    rewind(fp);

    buf = malloc((size_t)sz);
    if(!buf){
        fclose(fp);
        exit(1);
    }

    if(fread(buf, 1, (size_t)sz, fp) != (size_t)sz){
        free(buf);
        fclose(fp);
        exit(1);
    }
    fclose(fp);
    *out_size = (size_t)sz;
    return buf;
}

static void context_finalize(TSS2_TCTI_CONTEXT *tcti, ESYS_CONTEXT *esys){
    if(esys){
        Esys_Finalize(&esys);
        free(esys);
    }
    if(tcti){
        Tss2_TctiLdr_Finalize(&tcti);
        free(tcti);
    }
}

static void rc_check(TSS2_RC rc, TSS2_TCTI_CONTEXT *tcti, ESYS_CONTEXT *esys){
    if(rc != TSS2_RC_SUCCESS){
        printf("Failed:0x%x\n", rc);
        printf("%s\n", Tss2_RC_Decode(rc));
        context_finalize(tcti, esys);
        exit(1);
    }
}

static void save_signature(const TPMT_SIGNATURE *sig, const char *path){
    FILE *fp = fopen(path, "wb");
    if(!fp){
        perror("fopen");
        exit(1);
    }
    size_t written = fwrite(sig->signature.rsassa.sig.buffer, 1, sig->signature.rsassa.sig.size, fp);
    fclose(fp);

    if(written != sig->signature.rsassa.sig.size){
        fprintf(stderr, "failed to write signature file\n");
        exit(1);
    }
    printf("saved signature\n");
}

int main(int argc, char *argv[]){

    TSS2_RC rc;
    static ESYS_CONTEXT *es_ctx = NULL;
    static TSS2_TCTI_CONTEXT *tcti = NULL;
    TSS2_ABI_VERSION *CURRENT = NULL;
    ESYS_TR handle;



    rc = Tss2_TctiLdr_Initialize(NULL, &tcti);
    if(rc != TSS2_RC_SUCCESS){
        printf("tctildr initialize failed\n");
        free(es_ctx);
        return 1;
    }
    printf("tctildr initialize success\n");

    rc = Esys_Initialize(&es_ctx, tcti, CURRENT);
    if(rc != TSS2_RC_SUCCESS){
        printf("esys initialize failed:0x%x\n",rc);
        free(tcti);
        free(es_ctx);
        return 1;
    }

    printf("Initialize success\n");

    rc = Esys_TR_FromTPMPublic(
        es_ctx,
        0x81010100,   
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &handle
    );

    size_t data_size;
    TPM2B_MAX_BUFFER data;
    char *message = data_read(argv[1], &data_size);
    if(!message){
        fprintf(stderr, "Failed to read data\n");
        return 1;
    }

    data.size = data_size;
    memcpy(data.buffer, message, data.size);

    TPM2B_DIGEST *digest = NULL;
    TPMT_TK_HASHCHECK *validation = NULL;

    rc = Esys_Hash(
        es_ctx,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        &data,
        TPM2_ALG_SHA256,
        //ESYS_TR_RH_OWNER,
        ESYS_TR_RH_NULL,
        &digest,
        &validation
    );

    rc_check(rc, tcti, es_ctx);
    printf("hash OK\n");
    
    TPMT_SIG_SCHEME scheme = {
        .scheme = TPM2_ALG_RSASSA,
        .details.rsassa.hashAlg = TPM2_ALG_SHA256
    };

    TPMT_SIGNATURE *signature;

    rc = Esys_Sign(
            es_ctx,
            handle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            digest,
            &scheme,
            validation,
            &signature
            );

    rc_check(rc, tcti, es_ctx);
    printf("sign OK\n");

    save_signature(signature, "sig.bin");

    TPMT_TK_VERIFIED *valid;

    rc = Esys_VerifySignature(
            es_ctx,
            handle,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            digest,
            signature,
            &valid
            );
    rc_check(rc, tcti, es_ctx);
    printf("verify OK\n");

    TPML_DIGEST_VALUES ext_value;
    ext_value.count = 1;
    ext_value.digests -> hashAlg = TPM2_ALG_SHA256;
    memcpy(ext_value.digests -> digest.sha256, digest->buffer, digest->size);

    rc = Esys_PCR_Extend(
            es_ctx,
            ESYS_TR_PCR16,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &ext_value
            );
    rc_check(rc, tcti, es_ctx);
    printf("extend OK\n");

    TPM2B_DATA qualifyingData;
    qualifyingData.size = 20;
    TPM2B_DIGEST *nonce;

    rc = Esys_GetRandom(
            es_ctx,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            qualifyingData.size,
            &nonce
            );
    rc_check(rc, tcti, es_ctx);
    printf("nonce OK\n");

    memcpy(qualifyingData.buffer, nonce->buffer, qualifyingData.size);

    TPM2B_ATTEST *quoted;
    TPMT_SIGNATURE *signature_quote;

    /*
    pcrSelect[0] →  PCR 0 ～ 7
    pcrSelect[1] →  PCR 8 ～ 15
    pcrSelect[2] →  PCR 16 ～ 23
    */
    TPML_PCR_SELECTION Select_PCR;
    Select_PCR.count = 1;
    Select_PCR.pcrSelections -> hash = TPM2_ALG_SHA256;
    Select_PCR.pcrSelections -> sizeofSelect = 3;
    //Select_PCR.pcrSelections -> pcrSelect[0] = ;
    Select_PCR.pcrSelections -> pcrSelect[1] = 1 << 2;
    Select_PCR.pcrSelections -> pcrSelect[2] = 1;

    rc = Esys_Quote(
            es_ctx,
            handle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &qualifyingData,
            &scheme,
            &Select_PCR,
            &quoted,
            &signature_quote
            );
    rc_check(rc, tcti, es_ctx);
    printf("quote OK\n");

    save_signature(signature_quote, "sig_quote.bin");

    return 0;
}


