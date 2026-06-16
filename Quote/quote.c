#include <stdio.h>
#include "quote.h"
/*
#include <string.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_common.h>
*/
static void ctx_finalize(TSS2_TCTI_CONTEXT *tcti, TSS2_SYS_CONTEXT *sys){
    if(sys){
        Tss2_Sys_Finalize(sys);
        free(sys);
    }

    if(tcti){
        Tss2_TctiLdr_Finalize(&tcti);
        free(tcti);
    }
}

static void rc_check(TSS2_RC rc, TSS2_TCTI_CONTEXT *tcti, TSS2_SYS_CONTEXT *sys){
    if(rc != TSS2_RC_SUCCESS){
        printf("%s\n", Tss2_RC_Decode(rc));
            ctx_finalize(tcti, sys);
            exit(1);
    }
}
/*
static void save_signature(TPMT_SIGNATURE *sig, const char *path){
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
}

static void save_quote(TPM2B_ATTEST *quote, const char *path){
    FILE *fp = fopen(path, "wb");
    if(!fp){
        perror("fopen");
        exit(1);
    }

    size_t size = fwrite(quote->attestationData, 1, quote->size, fp);
    fclose(fp);

    if(size != quote->size){
        fprintf(stderr, "failed to write\n");
        exit(1);
    }
}
*/
int main(int argc, char *argv[]){
    TSS2_RC rc;
    size_t size;
    static TSS2_SYS_CONTEXT *s_ctx;
    static TSS2_TCTI_CONTEXT *t_ctx;
    TSS2_ABI_VERSION *CURRENT = NULL;
    const TPMI_DH_OBJECT handle = 0x81010010;

    rc = Tss2_TctiLdr_Initialize(NULL, &t_ctx);
    rc_check(rc, t_ctx, s_ctx);
    printf("tcti Initialize OK\n");

    size = Tss2_Sys_GetContextSize(0);
    s_ctx = (TSS2_SYS_CONTEXT*)calloc(1, size);

    rc = Tss2_Sys_Initialize(s_ctx, size, t_ctx, CURRENT);
    rc_check(rc, t_ctx, s_ctx);
    printf("sapi Initialize OK\n");

    TSS2L_SYS_AUTH_COMMAND CmdAuth = {0};
    CmdAuth.count = 1;
    CmdAuth.auths -> sessionHandle = TPM2_RS_PW;

    TPMT_SIG_SCHEME scheme;
    scheme.scheme = TPM2_ALG_RSASSA;
    scheme.details.rsassa.hashAlg = TPM2_ALG_SHA256;

    TSS2L_SYS_AUTH_RESPONSE rspAuth = {0};
    TPM2B_DATA qualifyingData;
    qualifyingData.size = 20;
    TPM2B_DIGEST nonce;

    rc = Tss2_Sys_GetRandom(
            s_ctx,
            NULL,
            qualifyingData.size,
            &nonce,
            &rspAuth
            );
    rc_check(rc, t_ctx, s_ctx);
    printf("nonce OK\n");
    
    memcpy(qualifyingData.buffer, nonce.buffer, qualifyingData.size);

    TPM2B_ATTEST quote;
    TPMT_SIGNATURE signature = {0};

    TPML_PCR_SELECTION Select_PCR;
    Select_PCR.count = 1;
    Select_PCR.pcrSelections -> hash = TPM2_ALG_SHA256;
    Select_PCR.pcrSelections -> sizeofSelect = 3;

    Select_PCR.pcrSelections -> pcrSelect[0] = 0;           //0~7
    Select_PCR.pcrSelections -> pcrSelect[1] = 1 << 2;      //8~15
    Select_PCR.pcrSelections -> pcrSelect[2] = 1;           //16~23

    rc = Tss2_Sys_Quote(
            s_ctx,
            handle,
            &CmdAuth,
            &qualifyingData,
            &scheme,
            &Select_PCR,
            &quote,
            &signature,
            &rspAuth
            );
    rc_check(rc, t_ctx, s_ctx);
    printf("quote OK\n");
/*
    save_signature(&signature, "sig.bin");
    printf("signature save OK\n");

    save_quote(&quote, "quote.bin");
    printf("quote save OK\n");
*/
    TPM2B_MAX_BUFFER data_quote;
    data_quote.size = quote.size;
    memcpy(data_quote.buffer, quote.attestationData, data_quote.size);

    TPM2B_DIGEST hash_quote = {0};
    TPMT_TK_HASHCHECK validation_quote;
    TPMT_TK_VERIFIED validation_verify_quote;

    rc = Tss2_Sys_Hash(
            s_ctx,
            NULL,
            &data_quote,
            TPM2_ALG_SHA256,
            TPM2_RH_NULL,
            &hash_quote,
            &validation_quote,
            NULL
            );
    rc_check(rc, t_ctx, s_ctx);
    printf("quote hash success\n");

    rc = Tss2_Sys_VerifySignature(
                    s_ctx,
                    handle,
                    NULL,
                    &hash_quote,
                    &signature,
                    &validation_verify_quote,
                    &rspAuth
                    );
    rc_check(rc, t_ctx, s_ctx);
    printf("quote verify success\n");

    ctx_finalize(t_ctx, s_ctx);
    return 0;
}
