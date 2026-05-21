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

static void save_signature(const TPMT_SIGNATURE *sig, const char *path){
    FILE *fp = fopen(path, "wb");
    if(!fp){
        perror("fopen");
        exit(1);
    }
    /*
    size_t written = fwrite(sig->signature.rsassa.sig.buffer, 1, sig->signature.rsassa.sig.size, fp);
    fclose(fp);

    if(written != sig->signature.rsassa.sig.size){
        fprintf(stderr, "failed to write signature file\n");
        exit(1);
    }
    */
    printf("saved signature\n");
}

int main(int argc, char *argv[]){
    TSS2_ABI_VERSION *CURRENT = NULL;
    size_t size;
    TSS2_SYS_CONTEXT *s_ctx = NULL;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    TSS2_RC rc;
    TPMI_DH_OBJECT hmac_handle = 0x81010001;
    TPMI_DH_OBJECT sign_handle = 0x81010010;

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
    if(rc != TSS2_RC_SUCCESS){
        printf("Hash failed:0x%x\n",rc);
        return 1;
    }
    printf("hash success\n");
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

    if(rc != TSS2_RC_SUCCESS){
        printf("Authsession failed:0x%x\n", rc);
        printf("%s\n", Tss2_RC_Decode(rc));
        return 1;
    }
    printf("Authsession succsess\n");

    TSS2L_SYS_AUTH_COMMAND CmdAuth;
    CmdAuth.count =  1;
    CmdAuth.auths -> sessionHandle = session_handle;
    CmdAuth.auths -> nonce.size = 0;
    CmdAuth.auths -> sessionAttributes = TPMA_SESSION_CONTINUESESSION;
    CmdAuth.auths -> hmac.size = 0;

    TPM2B_DIGEST *outHMAC;

    rc = Tss2_Sys_HMAC(
            s_ctx,
            hmac_handle,
            &CmdAuth,
            &data,
            TPM2_ALG_SHA256,
            outHMAC,
            &rspAuth);
    if(rc != TSS2_RC_SUCCESS){
        printf("HMAC failed:0x%x\n", rc);
        printf("%s\n", Tss2_RC_Decode(rc));
        return 1;
    }
    printf("HMAC success\n");

    TPMT_SIG_SCHEME scheme = {
        .scheme = TPM2_ALG_RSASSA,
        .details.rsassa.hashAlg = TPM2_ALG_SHA256
    };

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
    if(rc != TPM2_RC_SUCCESS){
        printf("Sign Failed:0x%x\n", rc);
        printf("%s\n", Tss2_RC_Decode(rc));
        free(s_ctx);
        free(tcti);
        return 1;
    };

    printf("sign success\n");

    if(!signature.signature.rsassa.sig.size){
        printf("yeah\n");
    }else{
        printf("size:%u\n", signature.signature.rsassa.sig.size);
    };

    //save_signature(signature, "sig.bin");
    

    if(s_ctx){
        Tss2_Sys_Finalize(s_ctx);
        free(s_ctx);
    }

    if(tcti){
        Tss2_TctiLdr_Finalize(&tcti);
        free(tcti);
    }
    return 0;
}
