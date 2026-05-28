#include <stdio.h>
#include <string.h>

#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_common.h>

static unsigned char *data_read(const char *path, size_t *out_size) {
    FILE *fp = fopen(path, "rb");
    unsigned char *buf;
    long sz;

    if(!fp){
        perror("fopen");
        return NULL;
    }

    if(fseek(fp, 0, SEEK_END) != 0){
        fclose(fp);
        return NULL;
    }

    sz = ftell(fp);
    if(sz < 0){
        fclose(fp);
        return NULL;
    }

    rewind(fp);

    buf = malloc((size_t)sz);
    if(!buf){
        fclose(fp);
        return NULL;
    }

    if(fread(buf, 1, (size_t)sz, fp) != (size_t)sz){
        free(buf);
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    *out_size = (size_t)sz;
    return buf;
}

static void context_finalize(TSS2_TCTI_CONTEXT *tcti, TSS2_SYS_CONTEXT *sys){
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
        printf("Failed:0x%x\n", rc);
        printf("%s\n", Tss2_RC_Decode(rc));
        context_finalize(tcti, sys);
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
    size_t size;
    static TSS2_SYS_CONTEXT *s_ctx = NULL;
    static TSS2_TCTI_CONTEXT *tcti = NULL;
    TSS2_ABI_VERSION *CURRENT = NULL;
    const TPMI_DH_OBJECT hmac_handle = 0x81010001;
    const TPMI_DH_OBJECT sign_handle = 0x81010010;

    //tcti = (TSS2_TCTI_CONTEXT*)calloc(1,size); 

    rc = Tss2_TctiLdr_Initialize(NULL, &tcti);
    if(rc != TSS2_RC_SUCCESS){
        printf("tctildr initialize failed\n");
        free(s_ctx);
        return 1;
    }
    printf("tctildr initialize success\n");

    size = Tss2_Sys_GetContextSize(0);
    //Tss2_Sys_GetTctiContext(sys, &tcti);
    s_ctx = (TSS2_SYS_CONTEXT*)calloc(1, size);

    rc = Tss2_Sys_Initialize(s_ctx, size, tcti, CURRENT);
    if(rc != TSS2_RC_SUCCESS){
        printf("sys initialize failed:0x%x\n",rc);
        free(tcti);
        free(s_ctx);
        return 1;
    }

    printf("Initialize success\n");
    
    size_t data_size;
    const char *message = data_read(argv[1], &data_size);
    if(!message){
        fprintf(stderr, "Failed to read data\n");
        return 1;
    }

    TPM2B_MAX_BUFFER data = { .size = data_size };
    memcpy(data.buffer, message, data.size);

    TPM2B_DIGEST hash = {0};
    TPMT_TK_HASHCHECK validation;

    rc = Tss2_Sys_Hash(
            s_ctx, 
            NULL, 
            &data, 
            TPM2_ALG_SHA256,
            TPM2_RH_NULL,
            &hash,
            &validation,
            NULL
            );
    rc_check(rc, tcti, s_ctx);
    printf("hash success\n");

    size_t data_dummy_size;
    const char *message_dummy = data_read(argv[2], &data_dummy_size);
    if(!message_dummy){
        fprintf(stderr, "Failed to read dummy data\n");
        return 1;
    }

    TPM2B_MAX_BUFFER data_dummy = { .size = data_dummy_size };
    memcpy(data.buffer, message_dummy, data.size);

    TPM2B_DIGEST hash_Dummy = {0};
    TPMT_TK_HASHCHECK validation_dummy;

    rc = Tss2_Sys_Hash(
            s_ctx,
            NULL,
            &data_dummy,
            TPM2_ALG_SHA256,
            TPM2_RH_NULL,
            &hash_Dummy,
            &validation_dummy,
            NULL);
    rc_check(rc, tcti, s_ctx);
    printf("dummy hash success\n");
/*
    printf("Hash(%u bytes): ", outHash.size);
    for(UINT16 i = 0; i < outHash.size; i++)
        printf("%02x", outHash.buffer[i]);
    printf("\n");
*/ 
    TPMI_SH_AUTH_SESSION session_handle = TPM2_RH_NULL;
    //Tss2_Sys_SetCmdAuths(s_ctx, &CmdAuth);
    TSS2L_SYS_AUTH_RESPONSE rspAuth = {0};
    TPM2B_NONCE nonceCaller = {0};
    TPM2B_NONCE nonceTPM = {0};
    nonceCaller.size = 20;
    memset(nonceCaller.buffer, 0, nonceCaller.size);
    
    TPMT_SYM_DEF symmetric = {0};
    symmetric.algorithm = TPM2_ALG_NULL;

    rc = Tss2_Sys_StartAuthSession(
            s_ctx,
            TPM2_RH_NULL,
            TPM2_RH_NULL,
            NULL,
            &nonceCaller,
            NULL,
            TPM2_SE_HMAC,
            &symmetric,
            TPM2_ALG_SHA256,
            &session_handle,
            &nonceTPM,
            &rspAuth);
    rc_check(rc, tcti, s_ctx);
    printf("Authsession succsess\n");

    TSS2L_SYS_AUTH_COMMAND CmdAuth;
    CmdAuth.count =  1;
    CmdAuth.auths -> sessionHandle = session_handle;
    CmdAuth.auths -> nonce.size = 0;
    CmdAuth.auths -> sessionAttributes = TPMA_SESSION_CONTINUESESSION;
    CmdAuth.auths -> hmac.size = 0;

    TPM2B_DIGEST outHMAC = {0};
    rc = Tss2_Sys_HMAC(
            s_ctx,
            hmac_handle,
            &CmdAuth,
            &data,
            TPM2_ALG_SHA256,
            &outHMAC,
            &rspAuth);
    rc_check(rc, tcti, s_ctx);
    printf("HMAC success\n");

    TPMT_SIG_SCHEME scheme = {
        .scheme = TPM2_ALG_RSASSA,
        .details.rsassa.hashAlg = TPM2_ALG_SHA256
    };

    TSS2L_SYS_AUTH_COMMAND CmdAuth_dummy;
    CmdAuth_dummy.count =  1;
    CmdAuth_dummy.auths -> sessionHandle = session_handle;
    CmdAuth_dummy.auths -> nonce.size = 0;
    CmdAuth_dummy.auths -> sessionAttributes = TPMA_SESSION_CONTINUESESSION;
    CmdAuth_dummy.auths -> hmac.size = 0;

    TPM2B_DIGEST outHMAC_dummy = {0};
    rc = Tss2_Sys_HMAC(
            s_ctx,
            hmac_handle,
            &CmdAuth_dummy,
            &data_dummy,
            TPM2_ALG_SHA256,
            &outHMAC,
            &rspAuth);
    rc_check(rc, tcti, s_ctx);
    printf("dummy HMAC success\n");
    if(memcmp(outHMAC.buffer, outHMAC_dummy.buffer, outHMAC.size) == 0)printf("valid\n");
    else{
        printf("invalid\n");
    }

    TPMT_SIGNATURE signature = {0};

    TSS2L_SYS_AUTH_COMMAND CmdAuth_sign = {0};
    CmdAuth_sign.count =  1;
    CmdAuth_sign.auths -> sessionHandle = TPM2_RS_PW;
    CmdAuth_sign.auths -> nonce.size = 0;
    CmdAuth_sign.auths -> sessionAttributes = 0;

    //printf("0x%x\n", signature->signature.rsassa.sig.size);
    rc = Tss2_Sys_Sign(
            s_ctx,
            sign_handle,
            &CmdAuth_sign,
            &hash,
            &scheme,
            &validation,
            &signature,
            &rspAuth);
    rc_check(rc, tcti, s_ctx);
    printf("sign success\n");

    if(!signature.signature.rsassa.sig.size)
        printf("No Signature\n");
    else{
        printf("size:%u\n", signature.signature.rsassa.sig.size);
    }

    //save_signature(&signature, "signature.bin");

    TPMT_TK_VERIFIED validation_verify;

    rc = Tss2_Sys_VerifySignature(
            s_ctx,
            sign_handle,
            //&CmdAuth_sign,
            NULL,
            &hash,
            &signature,
            &validation_verify,
            &rspAuth);
    rc_check(rc, tcti, s_ctx);
    printf("Verify success\n");
/*
    rc = Tss2_Sys_VerifySignature(
            s_ctx,
            sign_handle,
            //&CmdAuth_sign,
            NULL,
            &hash_Dummy,
            &signature,
            &validation_verify,
            &rspAuth);
    rc_check(rc, tcti, s_ctx);
    //printf("%s\n", Tss2_RC_Decode(rc));
*/
    TPM2B_DATA qualifyingData;
    qualifyingData.size = 0;

    TSS2L_SYS_AUTH_COMMAND CmdAuth_quote;
    CmdAuth_quote.count = 1;
    CmdAuth_quote.auths -> sessionHandle = TPM2_RS_PW;

    TPML_DIGEST_VALUES ext_value;
    ext_value.count = 1;
    ext_value.digests -> hashAlg = TPM2_ALG_SHA256;

    rc = Tss2_Sys_PCR_Extend(
            s_ctx,
            16,
            &CmdAuth_quote,
            &ext_value,
            &rspAuth
            );
    rc_check(rc, tcti, s_ctx);
    printf("extend success\n");

    TPM2B_ATTEST quoted;
    TPMT_SIGNATURE signature_quote;

    TPML_PCR_SELECTION Select_PCR;
    Select_PCR.count = 1;
    Select_PCR.pcrSelections -> hash = TPM2_ALG_SHA256;
    Select_PCR.pcrSelections -> sizeofSelect = 3;
    Select_PCR.pcrSelections -> pcrSelect[0] = 1 << 4;

    rc = Tss2_Sys_Quote(
            s_ctx,
            sign_handle,
            &CmdAuth_quote,
            &qualifyingData,
            &scheme,
            &Select_PCR,
            &quoted,
            &signature_quote,
            &rspAuth
            );
    rc_check(rc, tcti, s_ctx);
    printf("quote success\n");


    context_finalize(tcti, s_ctx);
    return 0;
}
