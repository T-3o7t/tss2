#include <stdio.h>
#include <string.h>

#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_common.h>

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

/*
    pcrSelect[0] →   PCR 0 ～ 7
    pcrSelect[1] →   PCR 8 ～ 15
    pcrSelect[2] →   PCR 16 ～ 23
*/
    TPML_PCR_SELECTION Select_PCR = {0};
    Select_PCR.count = 1;
    Select_PCR.pcrSelections[0].hash = TPM2_ALG_SHA256;
    Select_PCR.pcrSelections[0].sizeofSelect = 3;
    Select_PCR.pcrSelections[0].pcrSelect[0] = 0xFF;
    Select_PCR.pcrSelections[0].pcrSelect[1] = 0x00;
    Select_PCR.pcrSelections[0].pcrSelect[2] = 0x00;

	UINT32 counter;
	TPML_PCR_SELECTION *select_Out = NULL;
	TPML_DIGEST *pcrValues = NULL;	

	rc = Esys_PCR_Read(
		es_ctx,
		ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
		&Select_PCR,
		&counter,
		&select_Out,
		&pcrValues
		);
	rc_check(rc, t_ctx, es_ctx);

	Esys_Free(select_Out);
	Esys_Free(pcrValues);

    ctx_finalize(t_ctx, es_ctx);	
    return 0;
}
