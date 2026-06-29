#include <stdio.h>

#include <string.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_common.h>

//#include <tss2/tss2_mu.h>

static unsigned char *data_read(const char *path, size_t *out_size) {
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


static void ctx_finalize(TSS2_TCTI_CONTEXT *tcti, ESYS_CONTEXT *esys){
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
        ctx_finalize(tcti, esys);
        exit(1);
    }
}

//int test_quote(QuoteResult *result){
int main(void){
    TSS2_RC rc;
    static ESYS_CONTEXT *es_ctx = NULL;
    static TSS2_TCTI_CONTEXT *t_ctx = NULL;
    TSS2_ABI_VERSION *CURRENT = NULL;

    rc = Tss2_TctiLdr_Initialize(NULL, &t_ctx);
    if(rc != TSS2_RC_SUCCESS){
        printf("tctildr initialize failed\n");
        free(es_ctx);
        return 1;
    }
    printf("tctildr initialize success\n");

    rc = Esys_Initialize(&es_ctx, t_ctx, CURRENT);
    if(rc != TSS2_RC_SUCCESS){
        printf("esys initialize failed:0x%x\n",rc);
        free(t_ctx);
        free(es_ctx);
        return 1;
    }

    printf("Initialize success\n");

	TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = {.size = 0},
            .data     = {.size = 0},
        }
    };

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes =
                TPMA_OBJECT_FIXEDTPM |
                TPMA_OBJECT_FIXEDPARENT |
                TPMA_OBJECT_SENSITIVEDATAORIGIN |
                TPMA_OBJECT_USERWITHAUTH |
                TPMA_OBJECT_RESTRICTED |
                TPMA_OBJECT_DECRYPT,
            .authPolicy = {.size = 0},
            .parameters.rsaDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_AES,
                    .keyBits   = {.aes = 128},
                    .mode      = {.aes = TPM2_ALG_CFB}
                },
                .scheme = {
                    .scheme = TPM2_ALG_NULL,
                },
                .keyBits = 2048,
                .exponent = 0,
            },
            .unique.rsa = {.size = 0},
        }
    };

    TPM2B_DATA outsideInfo = {
        .size = 0,
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

	ESYS_TR primary_handle =ESYS_TR_NONE;
    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *primary_Data = NULL;
    TPM2B_DIGEST *primary_Hash = NULL;
	TPMT_TK_CREATION *primary_Ticket = NULL;

    rc = Esys_CreatePrimary(
            es_ctx,
            ESYS_TR_RH_OWNER,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &inSensitive,
            &inPublic,
            &outsideInfo,
            &creationPCR,
            &primary_handle,
            &outPublic,
            &primary_Data,
            &primary_Hash,
            &primary_Ticket
            );
    rc_check(rc, t_ctx, es_ctx);
    printf("Primary key created. Handle: 0x%x\n", primary_handle);

    TPM2B_PUBLIC ak_inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,

            .objectAttributes =
                TPMA_OBJECT_FIXEDTPM |
                TPMA_OBJECT_FIXEDPARENT |
                TPMA_OBJECT_SENSITIVEDATAORIGIN |
                TPMA_OBJECT_USERWITHAUTH |
                TPMA_OBJECT_SIGN_ENCRYPT |
                TPMA_OBJECT_RESTRICTED,

            .authPolicy = {.size = 0},
            .parameters.rsaDetail = {
                .symmetric = { .algorithm = TPM2_ALG_NULL },
                .scheme = {
                    .scheme = TPM2_ALG_RSASSA,
                    .details.rsassa.hashAlg = TPM2_ALG_SHA256
                },
                .keyBits = 2048,
                .exponent = 0,
            },
            .unique.rsa = {.size = 0},
        }
    };	

	TPM2B_PUBLIC *ak_pub = NULL;
    TPM2B_PRIVATE *ak_priv = NULL;
    TPM2B_CREATION_DATA *ak_Data = NULL;
    TPM2B_DIGEST *ak_Hash = NULL;
    TPMT_TK_CREATION *ak_Ticket = NULL;

    rc = Esys_Create(
            es_ctx,
            primary_handle,
	        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &inSensitive,
            &ak_inPublic,
            &outsideInfo,
            &creationPCR,
            &ak_priv,
            &ak_pub,
            &ak_Data,
            &ak_Hash,
            &ak_Ticket
            );
    rc_check(rc, t_ctx, es_ctx);
    printf("create ak OK\n");

    TPM2_HANDLE handle = ESYS_TR_NONE;

    rc = Esys_Load(
            es_ctx,
            primary_handle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            ak_priv,
            ak_pub,
            &handle
            );
    rc_check(rc, t_ctx, es_ctx);
    printf("load OK\n");
/*
    uint8_t ak_pub_buf[1024];
    size_t ak_offset = 0;

    rc = Tss2_MU_TPM2B_PUBLIC_Marshal(
            ak_pub,
            ak_pub_buf,
            sizeof(ak_pub_buf),
            &ak_offset
            );
    rc_check(rc, t_ctx, es_ctx);
    printf("Marshal OK\n");
    printf("Marshal size = %zu\n", ak_offset);	
*/

    TPM2B_ATTEST *quote;
    TPMT_SIGNATURE *signature;

    TPMT_SIG_SCHEME scheme = {
        .scheme = TPM2_ALG_RSASSA,
        .details.rsassa.hashAlg = TPM2_ALG_SHA256
    };

    /*
    pcrSelect[0] →   PCR 0 ～ 7
    pcrSelect[1] →   PCR 8 ～ 15
    pcrSelect[2] →   PCR 16 ～ 23
    */
    TPML_PCR_SELECTION Select_PCR;
    Select_PCR.count = 1;
    Select_PCR.pcrSelections -> hash = TPM2_ALG_SHA256;
    Select_PCR.pcrSelections -> sizeofSelect = 3;
    Select_PCR.pcrSelections -> pcrSelect[0] = 0x55;
    Select_PCR.pcrSelections -> pcrSelect[1] = 0x00;
    Select_PCR.pcrSelections -> pcrSelect[2] = 0x00;

    TPM2B_DATA qualifyingData;
    qualifyingData.size = 20;
	size_t nonce_size = qualifyingData.size;
	unsigned char *nonce = data_read("../nonce.bin", &nonce_size);
	memcpy(nonce, qualifyingData.buffer, nonce_size);

    rc = Esys_Quote(
            es_ctx,
            handle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &qualifyingData,
            &scheme,
            &Select_PCR,
            &quote,
            &signature
            );
    rc_check(rc, t_ctx, es_ctx);
    printf("quote OK\n");

	size_t check_size = quote->size;
	unsigned char *message = data_read("../quote.bin", &check_size);

    TPM2B_MAX_BUFFER data;
    data.size = check_size;
    memcpy(data.buffer, message, check_size);

    TPM2B_DIGEST *digest = NULL;
    TPMT_TK_HASHCHECK *validation = NULL;

    rc = Esys_Hash(
        es_ctx,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        &data,
        TPM2_ALG_SHA256,
        ESYS_TR_RH_NULL,
        &digest,
        &validation
    );
    rc_check(rc, t_ctx, es_ctx);
    printf("hash OK\n");


    TPMT_TK_VERIFIED *valid;
	TPMT_SIGNATURE *sig_check = calloc(1, sizeof(TPMT_SIGNATURE));
	size_t sig_size;
	unsigned char *sig_read = data_read("../sig.bin", &sig_size);

	sig_check->sigAlg = TPM2_ALG_RSASSA;
	sig_check->signature.rsassa.hash = TPM2_ALG_SHA256;
	sig_check->signature.rsassa.sig.size = sig_size;
	memcpy(sig_check->signature.rsassa.sig.buffer, sig_read, sig_size);

    rc = Esys_VerifySignature(
            es_ctx,
            handle,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            digest,
            sig_check,
            &valid
            );
    rc_check(rc, t_ctx, es_ctx);
    printf("verify OK\n");

	if(memcmp(quote->attestationData, message, quote->size)==0)
		printf("quote check OK\n");
	else
		printf("quote check failed\n");

	Esys_Free(outPublic);
    Esys_Free(primary_Data);
    Esys_Free(primary_Hash);
    Esys_Free(primary_Ticket);
    Esys_Free(ak_priv);
    Esys_Free(ak_pub);
    Esys_Free(ak_Data);
    Esys_Free(ak_Hash);
    Esys_Free(ak_Ticket);

    Esys_FlushContext(es_ctx, handle);
    Esys_FlushContext(es_ctx, primary_handle);

    ctx_finalize(t_ctx, es_ctx);	
    return 0;
}
